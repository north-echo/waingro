"""Build a deterministic identity for the exact artifact scope WAINGRO scans."""

from __future__ import annotations

import hashlib
from pathlib import Path

from waingro.models import ArtifactFileDigest, ArtifactIdentity, ParsedSkill


def _manifest_path(skill: ParsedSkill) -> Path:
    return skill.path / "SKILL.md"


def build_artifact_identity(skill: ParsedSkill) -> ArtifactIdentity:
    """Hash the manifest and eligible two-level bundled files without executing them."""
    manifest = _manifest_path(skill)
    records_by_path = {
        manifest: (skill.manifest_sha256, skill.manifest_size_bytes),
        **{
            bundled.path: (bundled.sha256, bundled.size_bytes)
            for bundled in skill.bundled_content
        },
    }
    records: list[ArtifactFileDigest] = []
    scope_digest = hashlib.sha256()
    total_bytes = 0

    for path in sorted(
        records_by_path,
        key=lambda item: item.relative_to(skill.path).as_posix(),
    ):
        relative = path.relative_to(skill.path).as_posix()
        file_digest, size = records_by_path[path]
        if file_digest is None or size is None:
            raise ValueError(f"artifact file lacks a scan-time digest: {path}")
        path_bytes = relative.encode("utf-8")
        scope_digest.update(len(path_bytes).to_bytes(8, "big"))
        scope_digest.update(path_bytes)
        scope_digest.update(size.to_bytes(8, "big"))
        scope_digest.update(bytes.fromhex(file_digest))
        total_bytes += size
        records.append(
            ArtifactFileDigest(
                path=relative,
                sha256=file_digest,
                size_bytes=size,
            )
        )

    return ArtifactIdentity(
        sha256=scope_digest.hexdigest(),
        file_count=len(records),
        total_bytes=total_bytes,
        files=records,
    )
