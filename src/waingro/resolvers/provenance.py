"""Optional cryptographic verification for Sigstore DSSE provenance bundles."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ProvenanceVerification:
    status: str
    payload: bytes | None = None
    reason: str | None = None


def github_repository_slug(repository_url: str | None) -> str | None:
    if not repository_url:
        return None
    value = repository_url.removeprefix("git+").removesuffix(".git").rstrip("/")
    if value.startswith("git@github.com:"):
        candidate = value.removeprefix("git@github.com:")
    else:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or parsed.hostname != "github.com":
            return None
        candidate = parsed.path.lstrip("/")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", candidate):
        return None
    return candidate


class SigstoreProvenanceVerifier:
    """Verify a bundle against Sigstore and an expected GitHub repository.

    ``sigstore`` is an optional dependency because static scanning must remain
    lightweight and offline.  No unsafe/no-op verification policy is used.
    """

    def __init__(self, *, offline: bool = False):
        self.offline = offline

    def __call__(
        self,
        bundle_data: dict,
        expected_repository_url: str | None,
    ) -> ProvenanceVerification:
        repository = github_repository_slug(expected_repository_url)
        if repository is None:
            return ProvenanceVerification(
                status="unavailable",
                reason="a canonical GitHub repository is required for identity policy",
            )
        try:
            from sigstore.errors import VerificationError
            from sigstore.models import Bundle, InvalidBundle
            from sigstore.verify import Verifier
            from sigstore.verify.policy import (
                AllOf,
                GitHubWorkflowRepository,
                OIDCIssuer,
            )
        except ImportError:
            return ProvenanceVerification(
                status="unavailable",
                reason="install WAINGRO with the provenance extra to verify Sigstore bundles",
            )
        try:
            bundle = Bundle.from_json(json.dumps(bundle_data))
            verifier = Verifier.production(offline=self.offline)
            policy = AllOf([
                OIDCIssuer("https://token.actions.githubusercontent.com"),
                GitHubWorkflowRepository(repository),
            ])
            payload_type, payload = verifier.verify_dsse(bundle, policy)
        except (InvalidBundle, VerificationError, ValueError, OSError) as exc:
            return ProvenanceVerification(status="failed", reason=str(exc)[:1000])
        if payload_type != "application/vnd.in-toto+json":
            return ProvenanceVerification(
                status="failed",
                reason=f"unexpected DSSE payload type: {payload_type}",
            )
        if len(payload) > 1024 * 1024:
            return ProvenanceVerification(
                status="failed",
                reason="verified provenance payload exceeded 1 MiB",
            )
        return ProvenanceVerification(status="verified", payload=payload)
