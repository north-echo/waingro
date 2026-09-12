"""Tests for bounded OSV package-version intelligence."""

from waingro.resolvers.osv import OsvError, query_vulnerabilities
from waingro.resolvers.package_registry import PackageResolution


def _resolution(name="example", version="1.0.0"):
    return PackageResolution(
        ecosystem="npm",
        name=name,
        requested=version,
        status="resolved",
        mutable=False,
        resolved_version=version,
    )


def test_osv_matches_vulnerabilities_and_malicious_package_advisories():
    def fetch(queries):
        assert queries == [{
            "version": "1.0.0",
            "package": {"ecosystem": "npm", "name": "example"},
        }]
        return {
            "results": [{
                "vulns": [
                    {"id": "GHSA-aaaa-bbbb-cccc", "modified": "2026-01-01T00:00:00Z"},
                    {"id": "MAL-2026-1234", "modified": "2026-02-01T00:00:00Z"},
                ]
            }]
        }

    [result] = query_vulnerabilities([_resolution()], fetch)

    assert result.status == "matched"
    assert [item.vulnerability_id for item in result.vulnerabilities] == [
        "GHSA-aaaa-bbbb-cccc",
        "MAL-2026-1234",
    ]
    assert result.vulnerabilities[1].malicious_package_advisory is True


def test_osv_errors_are_nonfatal_per_batch():
    def fetch(_queries):
        raise OsvError("HTTP 429; Retry-After=60")

    [result] = query_vulnerabilities([_resolution()], fetch)

    assert result.status == "error"
    assert "Retry-After=60" in (result.reason or "")


def test_osv_ignores_unresolved_and_unsupported_ecosystems():
    unresolved = PackageResolution(
        ecosystem="npm",
        name="example",
        requested="latest",
        status="unresolved",
        mutable=True,
    )
    unsupported = PackageResolution(
        ecosystem="cargo",
        name="example",
        requested="1.0.0",
        status="resolved",
        mutable=False,
        resolved_version="1.0.0",
    )

    assert query_vulnerabilities([unresolved, unsupported], lambda _: {}) == []
