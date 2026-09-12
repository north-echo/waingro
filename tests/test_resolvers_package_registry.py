"""Tests for non-executing package registry metadata resolution."""

import base64
import json
from pathlib import Path

import pytest

from waingro.models import PackageReference
from waingro.resolvers.package_registry import (
    RegistryMetadataClient,
    RegistryMetadataError,
    package_request,
    resolve_package_references,
)
from waingro.resolvers.provenance import ProvenanceVerification


def reference(
    runner: str,
    selector: str,
    *,
    immutable: bool = False,
    network_allowed: bool = True,
) -> PackageReference:
    return PackageReference(
        runner=runner,
        selector=selector,
        file_path=Path("scripts/run.js"),
        line_number=1,
        immutable=immutable,
        network_allowed=network_allowed,
    )


def test_normalizes_npm_and_pypi_selectors():
    npm = package_request(reference("npx", "@scope/tool@next"))
    pypi = package_request(reference("uvx", "markitdown[all]"))

    assert npm is not None
    assert (npm.ecosystem, npm.name, npm.requested, npm.mutable) == (
        "npm",
        "@scope/tool",
        "next",
        True,
    )
    assert pypi is not None
    assert (pypi.ecosystem, pypi.name, pypi.requested, pypi.mutable) == (
        "pypi",
        "markitdown",
        "latest",
        True,
    )
    pinned_pypi = package_request(reference("uvx", "ruff@0.12.1", immutable=True))
    assert pinned_pypi is not None
    assert (pinned_pypi.name, pinned_pypi.requested, pinned_pypi.mutable) == (
        "ruff",
        "0.12.1",
        False,
    )


def test_resolves_npm_tag_to_exact_version_and_integrity():
    calls = []

    def fetch(url):
        calls.append(url)
        return {
            "dist-tags": {"latest": "2.8.4"},
            "versions": {
                "2.8.4": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/degit/-/degit-2.8.4.tgz",
                        "integrity": "sha512-example",
                        "attestations": {"url": "https://registry.npmjs.org/-/npm/v1/attestations"},
                    }
                }
            },
            "time": {"2.8.4": "2022-03-01T00:00:00.000Z"},
        }

    resolutions = resolve_package_references(
        [reference("npx", "degit"), reference("npx", "degit")],
        fetch,
    )

    assert calls == ["https://registry.npmjs.org/degit"]
    assert len(resolutions) == 1
    resolved = resolutions[0]
    assert resolved.status == "resolved"
    assert resolved.resolved_version == "2.8.4"
    assert resolved.integrity == "sha512-example"
    assert resolved.provenance_present is True
    assert resolved.provenance_subject_matches is None
    assert resolved.provenance_reason == "registry attestation endpoint is not allowlisted"
    assert resolved.registry_signatures_present is False
    assert len(resolved.metadata_sha256 or "") == 64
    assert resolved.mutable is True


def test_npm_provenance_statement_binds_subject_to_registry_integrity():
    artifact_digest = b"\x01" * 64
    integrity = "sha512-" + base64.b64encode(artifact_digest).decode("ascii")
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "pkg:npm/degit@3.10.0",
                "digest": {"sha512": artifact_digest.hex()},
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "externalParameters": {
                    "workflow": {"repository": "https://github.com/Rich-Harris/degit"}
                },
                "resolvedDependencies": [
                    {"digest": {"gitCommit": "d" * 40}}
                ],
            }
        },
    }
    encoded_statement = base64.b64encode(
        json.dumps(statement).encode("utf-8")
    ).decode("ascii")
    attestation_url = (
        "https://registry.npmjs.org/-/npm/v1/attestations/degit@3.10.0"
    )

    def fetch(url):
        if url == attestation_url:
            return {
                "attestations": [
                    {
                        "predicateType": "https://slsa.dev/provenance/v1",
                        "bundle": {"dsseEnvelope": {"payload": encoded_statement}},
                    }
                ]
            }
        return {
            "dist-tags": {"latest": "3.10.0"},
            "versions": {
                "3.10.0": {
                    "dist": {
                        "integrity": integrity,
                        "attestations": {"url": attestation_url},
                    }
                }
            },
        }

    [resolved] = resolve_package_references([reference("npx", "degit")], fetch)

    assert resolved.provenance_subject_matches is True
    assert resolved.build_source_repository == "https://github.com/Rich-Harris/degit"
    assert resolved.build_source_revision == "d" * 40
    assert resolved.cryptographic_verification == "not-performed"
    assert resolved.provenance_reason == (
        "statement subject matches registry integrity; DSSE signature not verified"
    )
    assert len(resolved.provenance_statement_sha256 or "") == 64


def test_npm_provenance_can_be_cryptographically_verified():
    artifact_digest = b"\x02" * 64
    integrity = "sha512-" + base64.b64encode(artifact_digest).decode("ascii")
    statement = {
        "subject": [{
            "name": "pkg:npm/example@1.0.0",
            "digest": {"sha512": artifact_digest.hex()},
        }],
        "predicate": {"buildDefinition": {}},
    }
    payload = json.dumps(statement).encode()
    attestation_url = (
        "https://registry.npmjs.org/-/npm/v1/attestations/example@1.0.0"
    )

    def fetch(url):
        if url == attestation_url:
            return {
                "attestations": [{
                    "predicateType": "https://slsa.dev/provenance/v1",
                    "bundle": {
                        "dsseEnvelope": {
                            "payload": base64.b64encode(payload).decode("ascii")
                        }
                    },
                }]
            }
        return {
            "dist-tags": {"latest": "1.0.0"},
            "versions": {
                "1.0.0": {
                    "repository": "git+https://github.com/example/project.git",
                    "dist": {
                        "integrity": integrity,
                        "attestations": {"url": attestation_url},
                    },
                }
            },
        }

    def verify(bundle, repository):
        assert "dsseEnvelope" in bundle
        assert repository == "git+https://github.com/example/project.git"
        return ProvenanceVerification(status="verified", payload=payload)

    [resolved] = resolve_package_references(
        [reference("npx", "example")],
        fetch,
        verify,
    )

    assert resolved.cryptographic_verification == "verified"
    assert resolved.provenance_subject_matches is True
    assert "transparency evidence verified" in (resolved.provenance_reason or "")


def test_resolves_exact_npm_version_without_using_a_tag():
    def fetch(_url):
        return {
            "dist-tags": {"latest": "3.0.0"},
            "versions": {
                "2.8.4": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/degit/-/degit-2.8.4.tgz",
                        "shasum": "abc123",
                    }
                }
            },
        }

    [resolved] = resolve_package_references(
        [reference("npx", "degit@2.8.4", immutable=True)],
        fetch,
    )

    assert resolved.resolved_version == "2.8.4"
    assert resolved.integrity == "sha1-abc123"
    assert resolved.mutable is False


def test_resolves_pypi_metadata_without_downloading_an_artifact():
    def fetch(url):
        assert url == "https://pypi.org/pypi/markitdown/json"
        return {
            "info": {"version": "1.2.3"},
            "urls": [
                {
                    "packagetype": "sdist",
                    "url": "https://files.pythonhosted.org/packages/markitdown-1.2.3.tar.gz",
                    "digests": {"sha256": "deadbeef"},
                    "upload_time_iso_8601": "2026-01-02T03:04:05Z",
                }
            ],
        }

    [resolved] = resolve_package_references(
        [reference("uvx", "markitdown[all]")],
        fetch,
    )

    assert resolved.status == "resolved"
    assert resolved.resolved_version == "1.2.3"
    assert resolved.integrity == "sha256-deadbeef"
    assert resolved.provenance_present is None


def test_resolution_errors_and_local_only_references_are_nonfatal():
    def fetch(_url):
        raise RegistryMetadataError("HTTP 429; Retry-After=30")

    resolutions = resolve_package_references(
        [
            reference("npx", "prettier"),
            reference("npx", "tsc", network_allowed=False),
            reference("npx", "<dynamic>"),
        ],
        fetch,
    )

    assert [item.status for item in resolutions] == [
        "unresolved",
        "local-only",
        "unresolved",
    ]
    assert any("Retry-After=30" in (item.reason or "") for item in resolutions)


def test_registry_client_rejects_non_allowlisted_url_before_network_access():
    client = RegistryMetadataClient()

    with pytest.raises(RegistryMetadataError, match="not allowlisted"):
        client("https://example.com/package")

    with pytest.raises(RegistryMetadataError, match="not allowlisted"):
        client("https://registry.npmjs.org:444/package")
