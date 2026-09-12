"""Tests for bounded, non-executing dependency graph expansion."""

import base64
import hashlib
import io
import json
import tarfile

from waingro.resolvers.dependency_graph import resolve_dependency_graph
from waingro.resolvers.package_artifact import inspect_npm_artifact
from waingro.resolvers.package_registry import PackageResolution


def _archive(name: str, version: str, dependencies: dict[str, str]) -> bytes:
    package_json = json.dumps({
        "name": name,
        "version": version,
        "dependencies": dependencies,
    }).encode()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo("package/package.json")
        member.size = len(package_json)
        archive.addfile(member, io.BytesIO(package_json))
    return output.getvalue()


def _resolution(name: str, version: str, content: bytes) -> PackageResolution:
    integrity = base64.b64encode(hashlib.sha512(content).digest()).decode()
    return PackageResolution(
        ecosystem="npm",
        name=name,
        requested=version,
        status="resolved",
        mutable=False,
        resolved_version=version,
        integrity=f"sha512-{integrity}",
        artifact_url=f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
    )


def test_dependency_graph_resolves_exact_versions_and_preserves_unknown_ranges():
    root_archive = _archive("root", "1.0.0", {"exact-child": "2.0.0", "range-child": "^3.0.0"})
    exact_archive = _archive("exact-child", "2.0.0", {})
    root = _resolution("root", "1.0.0", root_archive)
    root_inspection = inspect_npm_artifact(root, root_archive)

    def metadata_fetch(url):
        name = url.rsplit("/", 1)[-1]
        if name == "exact-child":
            content = exact_archive
            integrity = base64.b64encode(hashlib.sha512(content).digest()).decode()
            return {
                "versions": {
                    "2.0.0": {
                        "dist": {
                            "integrity": f"sha512-{integrity}",
                            "tarball": (
                                "https://registry.npmjs.org/exact-child/-/"
                                "exact-child-2.0.0.tgz"
                            ),
                        }
                    }
                }
            }
        return {"versions": {"3.0.0": {"dist": {}}}}

    def artifact_fetch(url):
        assert "exact-child-2.0.0.tgz" in url
        return exact_archive

    graph = resolve_dependency_graph(
        [root],
        [root_inspection],
        metadata_fetch,
        artifact_fetch,
        max_depth=2,
    )

    assert len(graph.edges) == 2
    assert graph.unresolved_ranges == 1
    assert any(
        item.name == "exact-child" and item.status == "resolved"
        for item in graph.resolutions
    )
    assert any(
        item.name == "range-child" and item.status == "unresolved"
        for item in graph.resolutions
    )
    assert len(graph.inspections) == 1
    assert graph.inspections[0].status == "inspected"


def test_dependency_graph_applies_node_cap_to_roots():
    roots = [
        PackageResolution(
            ecosystem="npm",
            name=f"root-{index}",
            requested="1.0.0",
            status="resolved",
            mutable=False,
            resolved_version="1.0.0",
        )
        for index in range(3)
    ]

    graph = resolve_dependency_graph(
        roots,
        [],
        lambda _url: {},
        lambda _url: b"",
        max_nodes=2,
    )

    assert graph.truncated is True
    assert len(graph.roots) == 2
