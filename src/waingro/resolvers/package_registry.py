"""Resolve package-runner references through fixed official registry metadata APIs.

This module fetches JSON metadata only. It never invokes a package manager,
downloads an artifact, imports package code, or extracts an archive.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import ssl
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from waingro.models import PackageReference

NPM_HOST = "registry.npmjs.org"
PYPI_HOST = "pypi.org"
ALLOWED_HOSTS = frozenset({NPM_HOST, PYPI_HOST})
DEFAULT_MAX_METADATA_BYTES = 10 * 1024 * 1024
_PACKAGE_NAME_RE = re.compile(
    r"^(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*$"
)
_EXACT_VERSION_RE = re.compile(
    r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)


class MetadataFetcher(Protocol):
    def __call__(self, url: str) -> dict: ...


class RegistryMetadataError(RuntimeError):
    """Registry metadata could not be obtained or trusted."""


def _is_standard_https(url: str, host: str) -> bool:
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError:
        return False
    return parsed.scheme == "https" and parsed.hostname == host and port in {None, 443}


class _AllowlistRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        source = urlsplit(req.full_url)
        if not source.hostname or not _is_standard_https(newurl, source.hostname):
            raise RegistryMetadataError(f"registry redirect left allowlist: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass(frozen=True)
class PackageRequest:
    ecosystem: str
    name: str
    requested: str
    mutable: bool


@dataclass(frozen=True)
class PackageResolution:
    ecosystem: str
    name: str | None
    requested: str
    status: str
    mutable: bool
    resolved_version: str | None = None
    integrity: str | None = None
    artifact_url: str | None = None
    provenance_present: bool | None = None
    provenance_url: str | None = None
    provenance_subject_matches: bool | None = None
    provenance_statement_sha256: str | None = None
    build_source_repository: str | None = None
    build_source_revision: str | None = None
    cryptographic_verification: str | None = None
    provenance_reason: str | None = None
    registry_signatures_present: bool | None = None
    metadata_sha256: str | None = None
    published_at: str | None = None
    version_age_days: float | None = None
    package_created_at: str | None = None
    version_count: int | None = None
    maintainer_count: int | None = None
    repository_url: str | None = None
    git_head: str | None = None
    reason: str | None = None
    resolved_at: str | None = None

    def to_dict(self) -> dict:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "requested": self.requested,
            "status": self.status,
            "mutable": self.mutable,
            "resolved_version": self.resolved_version,
            "integrity": self.integrity,
            "artifact_url": self.artifact_url,
            "provenance_present": self.provenance_present,
            "provenance_url": self.provenance_url,
            "provenance_subject_matches": self.provenance_subject_matches,
            "provenance_statement_sha256": self.provenance_statement_sha256,
            "build_source_repository": self.build_source_repository,
            "build_source_revision": self.build_source_revision,
            "cryptographic_verification": self.cryptographic_verification,
            "provenance_reason": self.provenance_reason,
            "registry_signatures_present": self.registry_signatures_present,
            "metadata_sha256": self.metadata_sha256,
            "published_at": self.published_at,
            "version_age_days": self.version_age_days,
            "package_created_at": self.package_created_at,
            "version_count": self.version_count,
            "maintainer_count": self.maintainer_count,
            "repository_url": self.repository_url,
            "git_head": self.git_head,
            "reason": self.reason,
            "resolved_at": self.resolved_at,
        }


class RegistryMetadataClient:
    """Small allowlisted HTTPS client with bounded JSON responses."""

    def __init__(self, *, timeout: float = 5.0, max_bytes: int = DEFAULT_MAX_METADATA_BYTES):
        if timeout <= 0:
            raise ValueError("registry timeout must be positive")
        if max_bytes <= 0:
            raise ValueError("registry metadata byte limit must be positive")
        self.timeout = timeout
        self.max_bytes = max_bytes
        self._cache: dict[str, dict] = {}
        self._ssl_context = ssl.create_default_context()
        self._opener = build_opener(
            _AllowlistRedirectHandler(),
            HTTPSHandler(context=self._ssl_context),
        )

    def __call__(self, url: str) -> dict:
        if url in self._cache:
            return self._cache[url]
        parsed = urlsplit(url)
        if not parsed.hostname or (
            parsed.hostname not in ALLOWED_HOSTS
            or not _is_standard_https(url, parsed.hostname)
        ):
            raise RegistryMetadataError(f"registry URL is not allowlisted: {url}")
        request = Request(  # noqa: S310 -- URL host is fixed and checked above.
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "WAINGRO package-evidence resolver",
            },
        )
        try:
            with self._opener.open(  # noqa: S310 -- allowlisted HTTPS opener.
                request,
                timeout=self.timeout,
            ) as response:
                final_url = response.geturl()
                if not parsed.hostname or not _is_standard_https(final_url, parsed.hostname):
                    raise RegistryMetadataError(
                        f"registry response left allowlist: {final_url}"
                    )
                payload = response.read(self.max_bytes + 1)
        except HTTPError as exc:
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            detail = f"HTTP {exc.code}"
            if retry_after:
                detail += f"; Retry-After={retry_after}"
            raise RegistryMetadataError(detail) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise RegistryMetadataError(f"registry request failed: {exc}") from exc
        if len(payload) > self.max_bytes:
            raise RegistryMetadataError(
                f"registry metadata exceeded {self.max_bytes} bytes"
            )
        try:
            data = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RegistryMetadataError("registry returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise RegistryMetadataError("registry metadata root is not an object")
        self._cache[url] = data
        return data


def _npm_request(selector: str) -> PackageRequest | None:
    if selector == "<dynamic>" or selector.startswith((".", "/", "file:")):
        return None
    if selector.startswith("@"):
        slash = selector.find("/")
        separator = selector.find("@", slash + 1) if slash >= 0 else -1
    else:
        separator = selector.rfind("@")
    if separator > 0:
        name, requested = selector[:separator], selector[separator + 1 :]
    else:
        name, requested = selector, "latest"
    if not requested:
        requested = "latest"
    if not _PACKAGE_NAME_RE.fullmatch(name):
        return None
    return PackageRequest(
        ecosystem="npm",
        name=name,
        requested=requested,
        mutable=not bool(_EXACT_VERSION_RE.fullmatch(requested)),
    )


def _pypi_request(selector: str) -> PackageRequest | None:
    if selector == "<dynamic>" or selector.startswith((".", "/", "file:")):
        return None
    if "==" in selector:
        name, requested = selector.split("==", 1)
    elif "@" in selector and not selector.startswith("@"):
        name, requested = selector.rsplit("@", 1)
    else:
        name, requested = selector, "latest"
    name = name.split("[", 1)[0]
    if not _PACKAGE_NAME_RE.fullmatch(name):
        return None
    return PackageRequest(
        ecosystem="pypi",
        name=name,
        requested=requested,
        mutable=requested == "latest",
    )


def package_request(reference: PackageReference) -> PackageRequest | None:
    """Normalize a runner reference into an official registry request."""
    if reference.runner in {"npx", "pnpx", "bunx", "npm", "yarn", "pnpm"}:
        return _npm_request(reference.selector)
    if reference.runner in {"uvx", "pipx"}:
        return _pypi_request(reference.selector)
    return None


def _npm_resolution(request: PackageRequest, fetch: MetadataFetcher) -> PackageResolution:
    url = f"https://{NPM_HOST}/{quote(request.name, safe='@')}"
    metadata = fetch(url)
    if _EXACT_VERSION_RE.fullmatch(request.requested):
        version = request.requested
    else:
        tags = metadata.get("dist-tags")
        version = tags.get(request.requested) if isinstance(tags, dict) else None
        if not isinstance(version, str):
            return _unresolved(request, "npm range or tag could not be resolved exactly")
    versions = metadata.get("versions")
    version_data = versions.get(version) if isinstance(versions, dict) else None
    if not isinstance(version_data, dict):
        return _unresolved(request, f"npm metadata did not contain version {version}")
    dist = version_data.get("dist")
    dist = dist if isinstance(dist, dict) else {}
    artifact_url = dist.get("tarball") if isinstance(dist.get("tarball"), str) else None
    if artifact_url and not _is_standard_https(artifact_url, NPM_HOST):
        artifact_url = None
    integrity = dist.get("integrity") if isinstance(dist.get("integrity"), str) else None
    if integrity is None and isinstance(dist.get("shasum"), str):
        integrity = f"sha1-{dist['shasum']}"
    attestations = dist.get("attestations")
    signatures = dist.get("signatures")
    provenance_present = bool(attestations)
    registry_signatures_present = bool(signatures)
    provenance = _npm_provenance(
        attestations,
        name=request.name,
        version=version,
        integrity=integrity,
        fetch=fetch,
    )
    times = metadata.get("time")
    published_at = times.get(version) if isinstance(times, dict) else None
    created_at = times.get("created") if isinstance(times, dict) else None
    maintainers = version_data.get("maintainers")
    if not isinstance(maintainers, list):
        maintainers = metadata.get("maintainers")
    repository = version_data.get("repository")
    if not isinstance(repository, (dict, str)):
        repository = metadata.get("repository")
    repository_url = repository.get("url") if isinstance(repository, dict) else repository
    git_head = version_data.get("gitHead")
    return PackageResolution(
        ecosystem=request.ecosystem,
        name=request.name,
        requested=request.requested,
        status="resolved",
        mutable=request.mutable,
        resolved_version=version,
        integrity=integrity,
        artifact_url=artifact_url,
        provenance_present=provenance_present,
        provenance_url=provenance["url"],
        provenance_subject_matches=provenance["subject_matches"],
        provenance_statement_sha256=provenance["statement_sha256"],
        build_source_repository=provenance["repository"],
        build_source_revision=provenance["revision"],
        cryptographic_verification=provenance["cryptographic_verification"],
        provenance_reason=provenance["reason"],
        registry_signatures_present=registry_signatures_present,
        metadata_sha256=_metadata_sha256(metadata),
        published_at=published_at if isinstance(published_at, str) else None,
        version_age_days=_age_days(published_at),
        package_created_at=created_at if isinstance(created_at, str) else None,
        version_count=len(versions) if isinstance(versions, dict) else None,
        maintainer_count=len(maintainers) if isinstance(maintainers, list) else None,
        repository_url=repository_url if isinstance(repository_url, str) else None,
        git_head=git_head if isinstance(git_head, str) else None,
        resolved_at=datetime.now(UTC).isoformat(),
    )


def _pypi_resolution(request: PackageRequest, fetch: MetadataFetcher) -> PackageResolution:
    encoded_name = quote(request.name, safe="")
    if request.requested == "latest":
        url = f"https://{PYPI_HOST}/pypi/{encoded_name}/json"
    else:
        encoded_version = quote(request.requested, safe="")
        url = f"https://{PYPI_HOST}/pypi/{encoded_name}/{encoded_version}/json"
    metadata = fetch(url)
    info = metadata.get("info")
    info = info if isinstance(info, dict) else {}
    version = info.get("version")
    if not isinstance(version, str):
        return _unresolved(request, "PyPI metadata did not identify a version")
    urls = metadata.get("urls")
    artifacts = [item for item in urls if isinstance(item, dict)] if isinstance(urls, list) else []
    artifact = next((item for item in artifacts if item.get("packagetype") == "sdist"), None)
    artifact = artifact or (artifacts[0] if artifacts else {})
    artifact_url = artifact.get("url") if isinstance(artifact.get("url"), str) else None
    if artifact_url and not _is_standard_https(artifact_url, "files.pythonhosted.org"):
        artifact_url = None
    digests = artifact.get("digests")
    digest = digests.get("sha256") if isinstance(digests, dict) else None
    integrity = f"sha256-{digest}" if isinstance(digest, str) else None
    published_at = artifact.get("upload_time_iso_8601")
    releases = metadata.get("releases")
    maintainers = [
        value
        for value in (info.get("maintainer"), info.get("maintainer_email"))
        if isinstance(value, str) and value.strip()
    ]
    project_urls = info.get("project_urls")
    repository_url = None
    if isinstance(project_urls, dict):
        for key in ("Source", "Source Code", "Repository", "Homepage"):
            if isinstance(project_urls.get(key), str):
                repository_url = project_urls[key]
                break
    return PackageResolution(
        ecosystem=request.ecosystem,
        name=request.name,
        requested=request.requested,
        status="resolved",
        mutable=request.mutable,
        resolved_version=version,
        integrity=integrity,
        artifact_url=artifact_url,
        provenance_present=None,
        registry_signatures_present=None,
        metadata_sha256=_metadata_sha256(metadata),
        published_at=published_at if isinstance(published_at, str) else None,
        version_age_days=_age_days(published_at),
        version_count=len(releases) if isinstance(releases, dict) else None,
        maintainer_count=len(maintainers),
        repository_url=repository_url,
        resolved_at=datetime.now(UTC).isoformat(),
    )


def _unresolved(request: PackageRequest, reason: str) -> PackageResolution:
    return PackageResolution(
        ecosystem=request.ecosystem,
        name=request.name,
        requested=request.requested,
        status="unresolved",
        mutable=request.mutable,
        reason=reason,
    )


def _npm_provenance(
    attestations: object,
    *,
    name: str,
    version: str,
    integrity: str | None,
    fetch: MetadataFetcher,
) -> dict:
    result = {
        "url": None,
        "subject_matches": None,
        "statement_sha256": None,
        "repository": None,
        "revision": None,
        "cryptographic_verification": "not-performed",
        "reason": None,
    }
    if not isinstance(attestations, dict):
        result["reason"] = "registry metadata contains no attestation endpoint"
        return result
    url = attestations.get("url")
    if not isinstance(url, str):
        result["reason"] = "registry attestation endpoint is missing"
        return result
    if (
        not _is_standard_https(url, NPM_HOST)
        or not urlsplit(url).path.startswith("/-/npm/v1/attestations/")
    ):
        result["reason"] = "registry attestation endpoint is not allowlisted"
        return result
    result["url"] = url
    try:
        response = fetch(url)
    except RegistryMetadataError as exc:
        result["reason"] = f"attestation metadata unavailable: {exc}"
        return result
    entries = response.get("attestations")
    if not isinstance(entries, list):
        result["reason"] = "attestation response contains no statements"
        return result

    expected_digest = None
    if integrity and integrity.startswith("sha512-"):
        with suppress(ValueError, binascii.Error):
            expected_digest = base64.b64decode(
                integrity.removeprefix("sha512-"),
                validate=True,
            ).hex()

    expected_name = f"pkg:npm/{name}@{version}"
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("predicateType") != "https://slsa.dev/provenance/v1":
            continue
        bundle = entry.get("bundle")
        envelope = bundle.get("dsseEnvelope") if isinstance(bundle, dict) else None
        encoded = envelope.get("payload") if isinstance(envelope, dict) else None
        if not isinstance(encoded, str):
            continue
        try:
            payload = base64.b64decode(encoded, validate=True)
            if len(payload) > 1024 * 1024:
                result["reason"] = "attestation statement exceeded 1 MiB"
                return result
            statement = json.loads(payload)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError, binascii.Error):
            continue
        if not isinstance(statement, dict):
            continue
        result["statement_sha256"] = hashlib.sha256(payload).hexdigest()
        subjects = statement.get("subject")
        matching_subject = next(
            (
                subject
                for subject in subjects
                if isinstance(subject, dict) and subject.get("name") == expected_name
            ),
            None,
        ) if isinstance(subjects, list) else None
        digest = matching_subject.get("digest") if isinstance(matching_subject, dict) else None
        subject_digest = digest.get("sha512") if isinstance(digest, dict) else None
        result["subject_matches"] = bool(
            expected_digest
            and isinstance(subject_digest, str)
            and subject_digest.lower() == expected_digest.lower()
        )
        predicate = statement.get("predicate")
        definition = predicate.get("buildDefinition") if isinstance(predicate, dict) else None
        parameters = (
            definition.get("externalParameters") if isinstance(definition, dict) else None
        )
        workflow = parameters.get("workflow") if isinstance(parameters, dict) else None
        if isinstance(workflow, dict) and isinstance(workflow.get("repository"), str):
            result["repository"] = workflow["repository"]
        dependencies = (
            definition.get("resolvedDependencies") if isinstance(definition, dict) else None
        )
        if isinstance(dependencies, list):
            for dependency in dependencies:
                dependency_digest = (
                    dependency.get("digest") if isinstance(dependency, dict) else None
                )
                revision = (
                    dependency_digest.get("gitCommit")
                    if isinstance(dependency_digest, dict)
                    else None
                )
                if isinstance(revision, str):
                    result["revision"] = revision
                    break
        if result["subject_matches"]:
            result["reason"] = (
                "statement subject matches registry integrity; DSSE signature not verified"
            )
        else:
            result["reason"] = "statement subject does not match registry integrity"
        return result
    result["reason"] = "no SLSA provenance statement was found"
    return result


def _metadata_sha256(metadata: dict) -> str:
    canonical = json.dumps(
        metadata,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _age_days(timestamp: object) -> float | None:
    if not isinstance(timestamp, str):
        return None
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    age = datetime.now(UTC) - parsed.astimezone(UTC)
    return round(max(age.total_seconds(), 0.0) / 86_400, 3)


def resolve_package_references(
    references: list[PackageReference],
    fetch: MetadataFetcher,
) -> list[PackageResolution]:
    """Resolve unique network-capable registry references; keep failures non-fatal."""
    requests: dict[tuple[str, str, str], PackageRequest] = {}
    unresolved: list[PackageResolution] = []
    for reference in references:
        request = package_request(reference)
        if not reference.network_allowed:
            unresolved.append(
                PackageResolution(
                    ecosystem=request.ecosystem if request else "unknown",
                    name=request.name if request else None,
                    requested=request.requested if request else reference.selector,
                    status="local-only",
                    mutable=not reference.immutable,
                    reason="runner disables network installation",
                )
            )
            continue
        if request is None:
            unresolved.append(
                PackageResolution(
                    ecosystem="unknown",
                    name=None,
                    requested=reference.selector,
                    status="unresolved",
                    mutable=not reference.immutable,
                    reason="dynamic, local, or unsupported package selector",
                )
            )
            continue
        requests[(request.ecosystem, request.name, request.requested)] = request

    resolutions = []
    for request in requests.values():
        try:
            if request.ecosystem == "npm":
                resolution = _npm_resolution(request, fetch)
            else:
                resolution = _pypi_resolution(request, fetch)
        except RegistryMetadataError as exc:
            resolution = _unresolved(request, str(exc))
        resolutions.append(resolution)
    return sorted(
        [*resolutions, *unresolved],
        key=lambda item: (item.ecosystem, item.name or "", item.requested, item.status),
    )
