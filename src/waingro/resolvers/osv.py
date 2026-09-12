"""Bounded OSV queries for exact resolved package versions."""

from __future__ import annotations

import json
import ssl
import time
from dataclasses import dataclass, field
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from waingro.resolvers.http_safety import retry_after_seconds
from waingro.resolvers.package_registry import PackageResolution

OSV_URL = "https://api.osv.dev/v1/querybatch"
MAX_OSV_RESPONSE_BYTES = 10 * 1024 * 1024
MAX_BATCH = 100
MAX_PAGES = 10


class OsvError(RuntimeError):
    """OSV data was unavailable or malformed."""


class OsvFetcher(Protocol):
    def __call__(self, queries: list[dict]) -> dict: ...


class _OsvRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        parsed = urlsplit(newurl)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "api.osv.dev"
            or parsed.port not in {None, 443}
        ):
            raise OsvError(f"OSV redirect left allowlist: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass(frozen=True)
class VulnerabilityRecord:
    vulnerability_id: str
    modified: str | None = None

    @property
    def malicious_package_advisory(self) -> bool:
        return self.vulnerability_id.startswith("MAL-")

    def to_dict(self) -> dict:
        return {
            "id": self.vulnerability_id,
            "modified": self.modified,
            "malicious_package_advisory": self.malicious_package_advisory,
        }


@dataclass(frozen=True)
class PackageVulnerabilityResult:
    ecosystem: str
    name: str
    version: str
    status: str
    vulnerabilities: tuple[VulnerabilityRecord, ...] = field(default_factory=tuple)
    reason: str | None = None
    pages: int = 1

    def to_dict(self) -> dict:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "status": self.status,
            "vulnerabilities": [item.to_dict() for item in self.vulnerabilities],
            "reason": self.reason,
            "pages": self.pages,
        }


class OsvClient:
    def __init__(self, *, timeout: float = 10.0, max_bytes: int = MAX_OSV_RESPONSE_BYTES):
        if timeout <= 0 or max_bytes <= 0:
            raise ValueError("OSV timeout and byte limit must be positive")
        self.timeout = timeout
        self.max_bytes = max_bytes
        self._cooldown_until = 0.0
        self._opener = build_opener(
            _OsvRedirectHandler(),
            HTTPSHandler(context=ssl.create_default_context()),
        )

    def __call__(self, queries: list[dict]) -> dict:
        if not 1 <= len(queries) <= MAX_BATCH:
            raise OsvError(f"OSV batch must contain 1 to {MAX_BATCH} queries")
        remaining = self._cooldown_until - time.monotonic()
        if remaining > 0:
            raise OsvError(f"OSV rate-limit cooldown active; retry after {remaining:.1f}s")
        payload = json.dumps({"queries": queries}, separators=(",", ":")).encode()
        request = Request(  # noqa: S310 -- URL is a fixed HTTPS endpoint.
            OSV_URL,
            data=payload,
            method="POST",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "WAINGRO package intelligence resolver",
            },
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:  # noqa: S310
                if response.geturl() != OSV_URL:
                    raise OsvError("OSV response URL changed unexpectedly")
                content = response.read(self.max_bytes + 1)
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
            reason = f"HTTP {exc.code}"
            if retry_after:
                reason += f"; Retry-After={retry_after}"
            raise OsvError(reason) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise OsvError(f"OSV request failed: {exc}") from exc
        if len(content) > self.max_bytes:
            raise OsvError(f"OSV response exceeded {self.max_bytes} bytes")
        try:
            data = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OsvError("OSV returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise OsvError("OSV response root is not an object")
        return data


def _osv_ecosystem(ecosystem: str) -> str | None:
    return {"npm": "npm", "pypi": "PyPI"}.get(ecosystem)


def _records(raw: object) -> tuple[VulnerabilityRecord, ...]:
    if not isinstance(raw, list) or len(raw) > 3_000:
        raise OsvError("OSV vulnerability list is malformed or too large")
    records = []
    for item in raw:
        if not isinstance(item, dict):
            raise OsvError("OSV vulnerability item is not an object")
        identifier = item.get("id")
        modified = item.get("modified")
        if not isinstance(identifier, str) or not identifier or len(identifier) > 200:
            raise OsvError("OSV vulnerability identifier is invalid")
        if modified is not None and (not isinstance(modified, str) or len(modified) > 100):
            raise OsvError("OSV modified timestamp is invalid")
        records.append(VulnerabilityRecord(identifier, modified))
    unique = {item.vulnerability_id: item for item in records}
    return tuple(unique[key] for key in sorted(unique))


def query_vulnerabilities(
    resolutions: list[PackageResolution],
    fetch: OsvFetcher,
) -> list[PackageVulnerabilityResult]:
    """Query exact versions in bounded batches and preserve per-batch errors."""
    packages = []
    seen = set()
    for resolution in resolutions:
        osv_ecosystem = _osv_ecosystem(resolution.ecosystem)
        key = (osv_ecosystem, resolution.name, resolution.resolved_version)
        if (
            resolution.status != "resolved"
            or osv_ecosystem is None
            or not resolution.name
            or not resolution.resolved_version
            or key in seen
        ):
            continue
        seen.add(key)
        packages.append(key)

    output = []
    for offset in range(0, len(packages), MAX_BATCH):
        batch = packages[offset : offset + MAX_BATCH]
        queries = [
            {
                "version": version,
                "package": {"ecosystem": ecosystem, "name": name},
            }
            for ecosystem, name, version in batch
        ]
        try:
            response = fetch(queries)
            results = response.get("results")
            if not isinstance(results, list) or len(results) != len(batch):
                raise OsvError("OSV result count did not match query count")
        except OsvError as exc:
            output.extend(
                PackageVulnerabilityResult(
                    ecosystem=ecosystem,
                    name=name,
                    version=version,
                    status="error",
                    reason=str(exc),
                )
                for ecosystem, name, version in batch
            )
            continue
        for package, result in zip(batch, results, strict=True):
            ecosystem, name, version = package
            try:
                if not isinstance(result, dict):
                    raise OsvError("OSV package result is not an object")
                records = list(_records(result.get("vulns", [])))
                token = result.get("next_page_token")
                pages = 1
                while token is not None and pages < MAX_PAGES:
                    if not isinstance(token, str) or len(token) > 4096:
                        raise OsvError("OSV page token is invalid")
                    query = dict(queries[batch.index(package)])
                    query["page_token"] = token
                    page = fetch([query])
                    page_results = page.get("results")
                    if not isinstance(page_results, list) or len(page_results) != 1:
                        raise OsvError("OSV paginated result is malformed")
                    page_result = page_results[0]
                    if not isinstance(page_result, dict):
                        raise OsvError("OSV paginated package result is malformed")
                    records.extend(_records(page_result.get("vulns", [])))
                    token = page_result.get("next_page_token")
                    pages += 1
                if token is not None:
                    raise OsvError(f"OSV response exceeded {MAX_PAGES} pages")
                unique = {item.vulnerability_id: item for item in records}
                output.append(PackageVulnerabilityResult(
                    ecosystem=ecosystem,
                    name=name,
                    version=version,
                    status="matched" if unique else "clear",
                    vulnerabilities=tuple(unique[key] for key in sorted(unique)),
                    pages=pages,
                ))
            except OsvError as exc:
                output.append(PackageVulnerabilityResult(
                    ecosystem=ecosystem,
                    name=name,
                    version=version,
                    status="error",
                    reason=str(exc),
                ))
    return output
