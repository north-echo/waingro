"""Tests that live clients stop issuing requests during Retry-After windows."""

from urllib.error import HTTPError

import pytest

from waingro.resolvers.osv import OsvClient, OsvError
from waingro.resolvers.package_artifact import PackageArtifactClient, PackageArtifactError
from waingro.resolvers.package_registry import RegistryMetadataClient, RegistryMetadataError


class RateLimitedOpener:
    def __init__(self):
        self.calls = 0

    def open(self, request, **_kwargs):
        self.calls += 1
        raise HTTPError(
            request.full_url,
            429,
            "Too Many Requests",
            {"Retry-After": "60"},
            None,
        )


@pytest.mark.parametrize(
    ("client", "invoke", "error"),
    [
        (
            RegistryMetadataClient(),
            lambda client: client("https://registry.npmjs.org/example"),
            RegistryMetadataError,
        ),
        (
            PackageArtifactClient(),
            lambda client: client(
                "https://registry.npmjs.org/example/-/example-1.0.0.tgz"
            ),
            PackageArtifactError,
        ),
        (
            OsvClient(),
            lambda client: client([
                {
                    "version": "1.0.0",
                    "package": {"ecosystem": "npm", "name": "example"},
                }
            ]),
            OsvError,
        ),
    ],
)
def test_retry_after_opens_circuit_without_sleeping(client, invoke, error):
    opener = RateLimitedOpener()
    client._opener = opener

    with pytest.raises(error, match="Retry-After=60"):
        invoke(client)
    with pytest.raises(error, match="cooldown active"):
        invoke(client)

    assert opener.calls == 1
