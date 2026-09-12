"""Tests for bounded, non-extracting package artifact inspection."""

import base64
import hashlib
import io
import json
import tarfile
from dataclasses import replace

import pytest

from waingro.resolvers.package_artifact import (
    PackageArtifactClient,
    PackageArtifactError,
    inspect_npm_artifact,
    inspect_package_artifacts,
)
from waingro.resolvers.package_registry import PackageResolution


def npm_resolution(content: bytes, *, integrity_matches: bool = True) -> PackageResolution:
    digest = hashlib.sha512(content if integrity_matches else b"different").digest()
    return PackageResolution(
        ecosystem="npm",
        name="example-package",
        requested="latest",
        status="resolved",
        mutable=True,
        resolved_version="1.2.3",
        integrity="sha512-" + base64.b64encode(digest).decode("ascii"),
        artifact_url=(
            "https://registry.npmjs.org/example-package/-/example-package-1.2.3.tgz"
        ),
    )


def npm_tarball(*, unsafe_link: bool = False) -> bytes:
    package_json = json.dumps(
        {
            "name": "example-package",
            "version": "1.2.3",
            "scripts": {"postinstall": "node setup.js", "test": "pytest"},
            "dependencies": {"left-pad": "1.3.0"},
        }
    ).encode("utf-8")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        info = tarfile.TarInfo("package/package.json")
        info.size = len(package_json)
        archive.addfile(info, io.BytesIO(package_json))
        if unsafe_link:
            link = tarfile.TarInfo("package/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../outside"
            archive.addfile(link)
    return output.getvalue()


def test_inspects_verified_npm_archive_without_extracting():
    content = npm_tarball()

    inspected = inspect_npm_artifact(npm_resolution(content), content)

    assert inspected.status == "inspected"
    assert inspected.integrity_verified is True
    assert inspected.package_name_matches is True
    assert inspected.package_version_matches is True
    assert inspected.declared_lifecycle_scripts == {"postinstall": "node setup.js"}
    assert inspected.install_time_scripts == {"postinstall": "node setup.js"}
    assert inspected.prepare_script is None
    assert inspected.declared_dependency_count == 1
    assert inspected.declared_dependencies == {"left-pad": "1.3.0"}
    assert inspected.member_count == 1


def test_integrity_mismatch_stops_before_archive_parsing():
    content = b"not even a tar archive"

    inspected = inspect_npm_artifact(
        npm_resolution(content, integrity_matches=False),
        content,
    )

    assert inspected.status == "integrity-mismatch"
    assert inspected.member_count is None


def test_archive_links_are_recorded_as_unsafe():
    content = npm_tarball(unsafe_link=True)

    inspected = inspect_npm_artifact(npm_resolution(content), content)

    assert inspected.status == "unsafe-archive"
    assert inspected.unsafe_members == ["package/link"]


def test_package_identity_mismatch_is_not_a_successful_inspection():
    content = npm_tarball()
    resolution = replace(npm_resolution(content), resolved_version="9.9.9")

    inspected = inspect_npm_artifact(resolution, content)

    assert inspected.status == "identity-mismatch"
    assert inspected.package_version_matches is False


def test_archive_member_limit_is_nonfatal():
    content = npm_tarball()

    inspected = inspect_npm_artifact(
        npm_resolution(content),
        content,
        max_members=0,
    )

    assert inspected.status == "limit-exceeded"
    assert "0 members" in (inspected.reason or "")


def test_artifact_download_error_does_not_abort_other_results():
    content = npm_tarball()
    resolution = npm_resolution(content)

    def fetch(_url):
        raise PackageArtifactError("HTTP 429; Retry-After=60")

    [inspected] = inspect_package_artifacts([resolution], fetch)

    assert inspected.status == "download-error"
    assert "Retry-After=60" in (inspected.reason or "")


def test_artifact_client_rejects_non_allowlisted_url_before_network_access():
    client = PackageArtifactClient()

    with pytest.raises(PackageArtifactError, match="not allowlisted"):
        client("https://example.com/package.tgz")

    with pytest.raises(PackageArtifactError, match="not allowlisted"):
        client("https://registry.npmjs.org:444/package.tgz")
