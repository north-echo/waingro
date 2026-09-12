"""Bounded recursive dependency evidence without installation or execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from waingro.models import PackageReference
from waingro.resolvers.package_artifact import (
    ArtifactFetcher,
    PackageArtifactInspection,
    inspect_package_artifacts,
)
from waingro.resolvers.package_registry import (
    MetadataFetcher,
    PackageResolution,
    ProvenanceVerifier,
    resolve_package_references,
)


@dataclass(frozen=True)
class DependencyEdge:
    parent: str
    child: str
    requested: str
    depth: int

    def to_dict(self) -> dict:
        return {
            "parent": self.parent,
            "child": self.child,
            "requested": self.requested,
            "depth": self.depth,
        }


@dataclass
class DependencyGraph:
    roots: list[str] = field(default_factory=list)
    edges: list[DependencyEdge] = field(default_factory=list)
    resolutions: list[PackageResolution] = field(default_factory=list)
    inspections: list[PackageArtifactInspection] = field(default_factory=list)
    truncated: bool = False
    unresolved_ranges: int = 0
    max_depth: int = 0
    schema_version: str = "1.0"

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "roots": self.roots,
            "max_depth": self.max_depth,
            "truncated": self.truncated,
            "unresolved_ranges": self.unresolved_ranges,
            "edges": [edge.to_dict() for edge in self.edges],
            "resolutions": [item.to_dict() for item in self.resolutions],
            "inspections": [item.to_dict() for item in self.inspections],
        }


def _key(ecosystem: str, name: str | None, version: str | None) -> str:
    return f"{ecosystem}:{name or '<unknown>'}@{version or '<unresolved>'}"


def resolve_dependency_graph(
    roots: list[PackageResolution],
    root_inspections: list[PackageArtifactInspection],
    metadata_fetch: MetadataFetcher,
    artifact_fetch: ArtifactFetcher,
    *,
    max_depth: int = 3,
    max_nodes: int = 250,
    verify_provenance: ProvenanceVerifier | None = None,
) -> DependencyGraph:
    """Resolve and inspect exact or registry-tagged npm dependencies.

    Unsupported semver ranges remain explicit unresolved nodes.  WAINGRO does
    not guess at package-manager semantics because a wrong exact version would
    produce misleading provenance and vulnerability evidence.
    """
    if not 0 <= max_depth <= 5:
        raise ValueError("dependency depth must be between 0 and 5")
    if not 1 <= max_nodes <= 2_000:
        raise ValueError("dependency node limit must be between 1 and 2000")
    graph = DependencyGraph(max_depth=max_depth)
    inspections_by_key = {
        _key(item.ecosystem, item.name, item.version): item
        for item in root_inspections
    }
    queue: list[tuple[PackageResolution, int]] = []
    seen: set[str] = set()
    for resolution in roots:
        node = _key(resolution.ecosystem, resolution.name, resolution.resolved_version)
        if node in seen:
            continue
        if len(seen) >= max_nodes:
            graph.truncated = True
            break
        graph.roots.append(node)
        seen.add(node)
        if resolution.status == "resolved":
            queue.append((resolution, 0))

    while queue:
        parent, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        parent_key = _key(parent.ecosystem, parent.name, parent.resolved_version)
        inspection = inspections_by_key.get(parent_key)
        if inspection is None or inspection.status not in {"inspected", "inspected-unverified"}:
            continue
        references = [
            PackageReference(
                runner="npx",
                selector=f"{name}@{requested}",
                file_path=Path("<dependency-graph>"),
                line_number=0,
                immutable=False,
                network_allowed=True,
            )
            for name, requested in inspection.declared_dependencies.items()
        ]
        if len(seen) + len(references) > max_nodes:
            references = references[: max(0, max_nodes - len(seen))]
            graph.truncated = True
        children = resolve_package_references(
            references,
            metadata_fetch,
            verify_provenance,
        )
        fresh = []
        for child in children:
            child_key = _key(child.ecosystem, child.name, child.resolved_version)
            graph.edges.append(
                DependencyEdge(
                    parent=parent_key,
                    child=child_key,
                    requested=child.requested,
                    depth=depth + 1,
                )
            )
            if child.status != "resolved":
                graph.unresolved_ranges += 1
            if child_key in seen:
                continue
            seen.add(child_key)
            graph.resolutions.append(child)
            if child.status == "resolved":
                fresh.append(child)
        inspected = inspect_package_artifacts(fresh, artifact_fetch)
        graph.inspections.extend(inspected)
        inspections_by_key.update({
            _key(item.ecosystem, item.name, item.version): item
            for item in inspected
        })
        queue.extend((child, depth + 1) for child in fresh)
        if len(seen) >= max_nodes:
            graph.truncated = bool(queue) or graph.truncated
            break
    return graph
