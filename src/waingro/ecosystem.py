"""Artifact-bound ecosystem context supplied by corpus acquisition tooling."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_CONTEXT_BYTES = 1024 * 1024


@dataclass(frozen=True)
class EcosystemContext:
    artifact_sha256: str
    publisher_age_days: float | None = None
    publisher_skill_count: int | None = None
    skill_version_count: int | None = None
    source_matches_registry: bool | None = None
    publisher_verified: bool | None = None
    exact_artifact_malicious: bool = False
    intelligence_source: str | None = None
    schema_version: str = "1.0"

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "artifact_sha256": self.artifact_sha256,
            "publisher_age_days": self.publisher_age_days,
            "publisher_skill_count": self.publisher_skill_count,
            "skill_version_count": self.skill_version_count,
            "source_matches_registry": self.source_matches_registry,
            "publisher_verified": self.publisher_verified,
            "exact_artifact_malicious": self.exact_artifact_malicious,
            "intelligence_source": self.intelligence_source,
        }


def _optional_number(raw: dict, field: str) -> float | None:
    value = raw.get(field)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise ValueError(f"invalid ecosystem context field: {field}")
    return float(value)


def _optional_count(raw: dict, field: str) -> int | None:
    value = raw.get(field)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"invalid ecosystem context field: {field}")
    return value


def _optional_bool(raw: dict, field: str) -> bool | None:
    value = raw.get(field)
    if value is not None and not isinstance(value, bool):
        raise ValueError(f"invalid ecosystem context field: {field}")
    return value


def load_ecosystem_context(path: Path, expected_artifact_sha256: str) -> EcosystemContext:
    """Load bounded context that is bound to one exact artifact digest.

    Slugs and publisher names are intentionally insufficient.  This prevents a
    classification from being transferred to a different artifact that merely
    shares an author or name.
    """
    if path.is_symlink():
        raise ValueError("ecosystem context may not be a symlink")
    if path.stat().st_size > MAX_CONTEXT_BYTES:
        raise ValueError("ecosystem context exceeds 1 MiB")
    try:
        raw = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("ecosystem context is not valid JSON") from exc
    if not isinstance(raw, dict) or raw.get("schema_version") != "1.0":
        raise ValueError("unsupported ecosystem context schema")
    digest = raw.get("artifact_sha256")
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest.lower()):
        raise ValueError("ecosystem context has an invalid artifact SHA-256")
    digest = digest.lower()
    if digest != expected_artifact_sha256.lower():
        raise ValueError("ecosystem context artifact does not match scanned artifact")
    source = raw.get("intelligence_source")
    if source is not None and (
        not isinstance(source, str) or not source.startswith("https://") or len(source) > 2048
    ):
        raise ValueError("invalid ecosystem intelligence source")
    malicious = raw.get("exact_artifact_malicious", False)
    if not isinstance(malicious, bool):
        raise ValueError("invalid exact_artifact_malicious value")
    if malicious and not source:
        raise ValueError("malicious artifact intelligence requires a source URL")
    return EcosystemContext(
        artifact_sha256=digest,
        publisher_age_days=_optional_number(raw, "publisher_age_days"),
        publisher_skill_count=_optional_count(raw, "publisher_skill_count"),
        skill_version_count=_optional_count(raw, "skill_version_count"),
        source_matches_registry=_optional_bool(raw, "source_matches_registry"),
        publisher_verified=_optional_bool(raw, "publisher_verified"),
        exact_artifact_malicious=malicious,
        intelligence_source=source,
    )
