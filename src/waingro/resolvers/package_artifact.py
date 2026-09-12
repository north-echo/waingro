"""Bounded, non-extracting inspection of resolved package archives.

Candidate package code is never imported or executed. Archive inspection is
intended for an isolated analysis host despite these parser-level safeguards.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import ssl
import tarfile
import time
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from waingro.resolvers.http_safety import retry_after_seconds
from waingro.resolvers.package_registry import PackageResolution

NPM_ARTIFACT_HOST = "registry.npmjs.org"
DEFAULT_MAX_ARTIFACT_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_MEMBERS = 10_000
MAX_PACKAGE_JSON_BYTES = 1024 * 1024
LIFECYCLE_NAMES = ("preinstall", "install", "postinstall", "prepare")


class ArtifactFetcher(Protocol):
    def __call__(self, url: str) -> bytes: ...


class PackageArtifactError(RuntimeError):
    """A package archive could not be obtained or inspected safely."""


def _is_standard_npm_https(url: str) -> bool:
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname == NPM_ARTIFACT_HOST
        and port in {None, 443}
    )


class _SameHostRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        source = urlsplit(req.full_url)
        if not source.hostname or not _is_standard_npm_https(newurl):
            raise PackageArtifactError(f"artifact redirect left allowlist: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass(frozen=True)
class PackageArtifactInspection:
    ecosystem: str
    name: str | None
    version: str | None
    status: str
    artifact_url: str | None
    archive_sha256: str | None = None
    integrity_verified: bool | None = None
    integrity_algorithm: str | None = None
    package_name_matches: bool | None = None
    package_version_matches: bool | None = None
    member_count: int | None = None
    uncompressed_bytes: int | None = None
    unsafe_members: list[str] = field(default_factory=list)
    declared_lifecycle_scripts: dict[str, str] = field(default_factory=dict)
    install_time_scripts: dict[str, str] = field(default_factory=dict)
    prepare_script: str | None = None
    declared_dependency_count: int | None = None
    declared_dependencies: dict[str, str] = field(default_factory=dict)
    reason: str | None = None

    def to_dict(self) -> dict:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "status": self.status,
            "artifact_url": self.artifact_url,
            "archive_sha256": self.archive_sha256,
            "integrity_verified": self.integrity_verified,
            "integrity_algorithm": self.integrity_algorithm,
            "package_name_matches": self.package_name_matches,
            "package_version_matches": self.package_version_matches,
            "member_count": self.member_count,
            "uncompressed_bytes": self.uncompressed_bytes,
            "unsafe_members": self.unsafe_members,
            "declared_lifecycle_scripts": self.declared_lifecycle_scripts,
            "install_time_scripts": self.install_time_scripts,
            "prepare_script": self.prepare_script,
            "declared_dependency_count": self.declared_dependency_count,
            "declared_dependencies": self.declared_dependencies,
            "reason": self.reason,
        }


class PackageArtifactClient:
    """Download a bounded npm archive from the exact resolved registry URL."""

    def __init__(self, *, timeout: float = 15.0, max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES):
        if timeout <= 0:
            raise ValueError("artifact timeout must be positive")
        if max_bytes <= 0:
            raise ValueError("artifact byte limit must be positive")
        self.timeout = timeout
        self.max_bytes = max_bytes
        context = ssl.create_default_context()
        self._opener = build_opener(
            _SameHostRedirectHandler(),
            HTTPSHandler(context=context),
        )
        self._cache: dict[str, bytes] = {}
        self._cooldown_until = 0.0

    def __call__(self, url: str) -> bytes:
        if url in self._cache:
            return self._cache[url]
        remaining = self._cooldown_until - time.monotonic()
        if remaining > 0:
            raise PackageArtifactError(
                f"artifact rate-limit cooldown active; retry after {remaining:.1f}s"
            )
        if not _is_standard_npm_https(url):
            raise PackageArtifactError(f"artifact URL is not allowlisted: {url}")
        request = Request(  # noqa: S310 -- fixed registry host checked above.
            url,
            headers={
                "Accept": "application/octet-stream",
                "User-Agent": "WAINGRO inert package inspector",
            },
        )
        try:
            with self._opener.open(  # noqa: S310 -- allowlisted HTTPS opener.
                request,
                timeout=self.timeout,
            ) as response:
                if not _is_standard_npm_https(response.geturl()):
                    raise PackageArtifactError(
                        f"artifact response left allowlist: {response.geturl()}"
                    )
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > self.max_bytes:
                    raise PackageArtifactError(
                        f"artifact Content-Length exceeded {self.max_bytes} bytes"
                    )
                payload = response.read(self.max_bytes + 1)
        except HTTPError as exc:
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            cooldown = retry_after_seconds(retry_after)
            if exc.code == 429 and cooldown is None:
                cooldown = 60
            if cooldown is not None:
                self._cooldown_until = max(
                    self._cooldown_until,
                    time.monotonic() + cooldown,
                )
            detail = f"HTTP {exc.code}"
            if retry_after:
                detail += f"; Retry-After={retry_after}"
            raise PackageArtifactError(detail) from exc
        except (URLError, TimeoutError, OSError, ValueError) as exc:
            raise PackageArtifactError(f"artifact request failed: {exc}") from exc
        if len(payload) > self.max_bytes:
            raise PackageArtifactError(f"artifact exceeded {self.max_bytes} bytes")
        self._cache[url] = payload
        return payload


def _verify_integrity(content: bytes, integrity: str | None) -> tuple[bool | None, str | None]:
    if not integrity or "-" not in integrity:
        return None, None
    algorithm, expected = integrity.split("-", 1)
    algorithm = algorithm.lower()
    if algorithm == "sha512":
        actual = hashlib.sha512(content).digest()
        try:
            return actual == base64.b64decode(expected, validate=True), algorithm
        except (ValueError, binascii.Error):
            return False, algorithm
    if algorithm == "sha1":
        return hashlib.sha1(content, usedforsecurity=False).hexdigest() == expected, algorithm
    return None, algorithm


def _unsafe_member(member: tarfile.TarInfo) -> bool:
    path = PurePosixPath(member.name)
    return (
        path.is_absolute()
        or ".." in path.parts
        or member.issym()
        or member.islnk()
        or not (member.isfile() or member.isdir())
    )


def inspect_npm_artifact(
    resolution: PackageResolution,
    content: bytes,
    *,
    max_uncompressed_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES,
    max_members: int = DEFAULT_MAX_MEMBERS,
) -> PackageArtifactInspection:
    """Verify and stream-inspect an npm tarball without extracting it."""
    archive_sha256 = hashlib.sha256(content).hexdigest()
    integrity_verified, integrity_algorithm = _verify_integrity(
        content,
        resolution.integrity,
    )
    base = {
        "ecosystem": resolution.ecosystem,
        "name": resolution.name,
        "version": resolution.resolved_version,
        "artifact_url": resolution.artifact_url,
        "archive_sha256": archive_sha256,
        "integrity_verified": integrity_verified,
        "integrity_algorithm": integrity_algorithm,
    }
    if integrity_verified is False:
        return PackageArtifactInspection(
            **base,
            status="integrity-mismatch",
            reason="downloaded bytes do not match registry integrity",
        )

    member_count = 0
    uncompressed_bytes = 0
    unsafe_members: list[str] = []
    package_data = None
    try:
        with tarfile.open(fileobj=io.BytesIO(content), mode="r|gz") as archive:
            for member in archive:
                member_count += 1
                if member_count > max_members:
                    raise PackageArtifactError(f"archive exceeded {max_members} members")
                if _unsafe_member(member):
                    if len(unsafe_members) < 20:
                        unsafe_members.append(member.name[:300])
                    continue
                if not member.isfile():
                    continue
                uncompressed_bytes += member.size
                if uncompressed_bytes > max_uncompressed_bytes:
                    raise PackageArtifactError(
                        f"archive exceeded {max_uncompressed_bytes} declared bytes"
                    )
                if member.name != "package/package.json":
                    continue
                if member.size > MAX_PACKAGE_JSON_BYTES:
                    raise PackageArtifactError("package.json exceeded 1 MiB")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise PackageArtifactError("package.json could not be read")
                raw = extracted.read(MAX_PACKAGE_JSON_BYTES + 1)
                if len(raw) > MAX_PACKAGE_JSON_BYTES:
                    raise PackageArtifactError("package.json exceeded 1 MiB")
                package_data = json.loads(raw)
    except (tarfile.TarError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return PackageArtifactInspection(
            **base,
            status="invalid-archive",
            member_count=member_count,
            uncompressed_bytes=uncompressed_bytes,
            unsafe_members=unsafe_members,
            reason=f"archive parsing failed: {exc}",
        )
    except PackageArtifactError as exc:
        return PackageArtifactInspection(
            **base,
            status="limit-exceeded",
            member_count=member_count,
            uncompressed_bytes=uncompressed_bytes,
            unsafe_members=unsafe_members,
            reason=str(exc),
        )

    package_name_matches = (
        package_data.get("name") == resolution.name
        if isinstance(package_data, dict)
        else None
    )
    package_version_matches = (
        package_data.get("version") == resolution.resolved_version
        if isinstance(package_data, dict)
        else None
    )
    if unsafe_members:
        status = "unsafe-archive"
        reason = "archive contains link, traversal, or special-file members"
    elif not isinstance(package_data, dict):
        status = "invalid-archive"
        reason = "archive contains no package/package.json object"
    elif not package_name_matches or not package_version_matches:
        status = "identity-mismatch"
        reason = "package.json name or version does not match registry resolution"
    elif integrity_verified is None:
        status = "inspected-unverified"
        reason = "registry metadata supplied no supported artifact integrity"
    else:
        status = "inspected"
        reason = None
    scripts = package_data.get("scripts") if isinstance(package_data, dict) else None
    declared_lifecycle_scripts = {
        name: scripts[name]
        for name in LIFECYCLE_NAMES
        if isinstance(scripts, dict) and isinstance(scripts.get(name), str)
    }
    install_time_scripts = {
        name: value
        for name, value in declared_lifecycle_scripts.items()
        if name in {"preinstall", "install", "postinstall"}
    }
    dependency_count = None
    declared_dependencies: dict[str, str] = {}
    if isinstance(package_data, dict):
        for field in ("dependencies", "optionalDependencies"):
            values = package_data.get(field)
            if not isinstance(values, dict):
                continue
            for dependency_name, selector in values.items():
                if (
                    isinstance(dependency_name, str)
                    and isinstance(selector, str)
                    and len(dependency_name) <= 214
                    and len(selector) <= 512
                    and len(declared_dependencies) < 2_000
                ):
                    declared_dependencies[dependency_name] = selector
        dependency_count = len(declared_dependencies)
    return PackageArtifactInspection(
        **base,
        status=status,
        package_name_matches=package_name_matches,
        package_version_matches=package_version_matches,
        member_count=member_count,
        uncompressed_bytes=uncompressed_bytes,
        unsafe_members=unsafe_members,
        declared_lifecycle_scripts=declared_lifecycle_scripts,
        install_time_scripts=install_time_scripts,
        prepare_script=declared_lifecycle_scripts.get("prepare"),
        declared_dependency_count=dependency_count,
        declared_dependencies=dict(sorted(declared_dependencies.items())),
        reason=reason,
    )


def inspect_package_artifacts(
    resolutions: list[PackageResolution],
    fetch: ArtifactFetcher,
) -> list[PackageArtifactInspection]:
    """Inspect each unique supported artifact while keeping failures non-fatal."""
    inspections = []
    seen = set()
    for resolution in resolutions:
        key = (resolution.ecosystem, resolution.name, resolution.resolved_version)
        if key in seen or resolution.status != "resolved":
            continue
        seen.add(key)
        if resolution.ecosystem != "npm" or not resolution.artifact_url:
            continue
        try:
            content = fetch(resolution.artifact_url)
        except PackageArtifactError as exc:
            inspections.append(
                PackageArtifactInspection(
                    ecosystem=resolution.ecosystem,
                    name=resolution.name,
                    version=resolution.resolved_version,
                    status="download-error",
                    artifact_url=resolution.artifact_url,
                    reason=str(exc),
                )
            )
            continue
        inspections.append(inspect_npm_artifact(resolution, content))
    return inspections
