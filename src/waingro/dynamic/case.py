"""Validate non-executing dynamic-analysis case dossiers."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath

from waingro.parsers.script import read_file_bytes
from waingro.scanner import scan_skill

MAX_CASE_BYTES = 256 * 1024
MAX_FIXTURE_BYTES = 1024 * 1024
MAX_FIXTURES = 16
MAX_HYPOTHESES = 32
MAX_ENTRYPOINTS = 32
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ENTRYPOINT_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?$")
_REQUIRED_CONTROLS = {
    "benign-canary",
    "negative-control",
    "posture-before",
    "posture-after",
    "destroy-guest",
}


class DynamicCaseError(ValueError):
    """A case dossier violates the pre-execution safety contract."""


def _non_symlink_path(path: Path, *, label: str) -> Path:
    absolute = path.absolute()
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise DynamicCaseError(f"{label} could not be resolved safely") from exc
    if absolute != resolved:
        raise DynamicCaseError(f"{label} path must not traverse a symlink")
    return absolute


def _json_object(path: Path, *, max_bytes: int, label: str) -> tuple[dict, bytes]:
    if path.is_symlink() or not path.is_file():
        raise DynamicCaseError(f"{label} must be a non-symlink JSON file")
    if path.stat().st_size > max_bytes:
        raise DynamicCaseError(f"{label} exceeds {max_bytes} bytes")
    try:
        content = read_file_bytes(path)
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DynamicCaseError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise DynamicCaseError(f"{label} root is not an object")
    return value, content


def _string_list(value: object, *, label: str, maximum: int) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > maximum
        or any(not isinstance(item, str) or not item or len(item) > 2000 for item in value)
    ):
        raise DynamicCaseError(f"{label} is invalid")
    return value


def _fixture_records(case_path: Path, raw: object) -> list[dict]:
    if not isinstance(raw, list) or not raw or len(raw) > MAX_FIXTURES:
        raise DynamicCaseError("case fixtures are invalid")
    records = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise DynamicCaseError("case fixture entry is not an object")
        relative_value = item.get("path")
        expected = item.get("sha256")
        if not isinstance(relative_value, str) or not _ENTRYPOINT_RE.fullmatch(relative_value):
            raise DynamicCaseError("case fixture path violates policy")
        relative = PurePosixPath(relative_value)
        if relative.is_absolute() or ".." in relative.parts or len(relative.parts) > 2:
            raise DynamicCaseError("case fixture path violates policy")
        if (
            relative_value in seen
            or not isinstance(expected, str)
            or not _DIGEST_RE.fullmatch(expected)
            or not isinstance(item.get("purpose"), str)
            or not item["purpose"]
            or len(item["purpose"]) > 1000
        ):
            raise DynamicCaseError("case fixture identity is invalid")
        seen.add(relative_value)
        fixture = _non_symlink_path(
            case_path.parent / relative_value,
            label="case fixture",
        )
        _parsed, content = _json_object(
            fixture,
            max_bytes=MAX_FIXTURE_BYTES,
            label="case fixture",
        )
        observed = hashlib.sha256(content).hexdigest()
        if observed != expected:
            raise DynamicCaseError(f"case fixture SHA-256 mismatch: {relative_value}")
        records.append({"path": relative_value, "sha256": observed, "size_bytes": len(content)})
    return records


def _entrypoint_records(value: object) -> list[dict]:
    if not isinstance(value, list) or not value or len(value) > MAX_ENTRYPOINTS:
        raise DynamicCaseError("proposed entrypoints are invalid")
    records = []
    seen: set[str] = set()
    suffixes = {"python": ".py", "node": (".js", ".mjs", ".cjs"), "shell": ".sh"}
    for item in value:
        if not isinstance(item, dict):
            raise DynamicCaseError("proposed entrypoint is not an object")
        path_value = item.get("path")
        interpreter = item.get("interpreter")
        if (
            not isinstance(path_value, str)
            or not _ENTRYPOINT_RE.fullmatch(path_value)
            or path_value in seen
            or interpreter not in suffixes
            or item.get("execute") is not False
        ):
            raise DynamicCaseError("proposed entrypoint violates the non-execution policy")
        path = PurePosixPath(path_value)
        expected_suffix = suffixes[interpreter]
        if path.is_absolute() or ".." in path.parts or len(path.parts) > 2:
            raise DynamicCaseError("proposed entrypoint path violates policy")
        if (isinstance(expected_suffix, tuple) and path.suffix.lower() not in expected_suffix) or (
            isinstance(expected_suffix, str) and path.suffix.lower() != expected_suffix
        ):
            raise DynamicCaseError("proposed entrypoint interpreter does not match its suffix")
        seen.add(path_value)
        records.append({"path": path_value, "interpreter": interpreter, "execute": False})
    return records


def validate_dynamic_case(case_path: Path, candidate: Path | None = None) -> dict:
    """Validate a case dossier and optional candidate without creating an execution plan."""
    case_path = _non_symlink_path(case_path, label="dynamic case")
    raw, content = _json_object(case_path, max_bytes=MAX_CASE_BYTES, label="dynamic case")
    if raw.get("schema_version") != "1.0":
        raise DynamicCaseError("unsupported dynamic-case schema")
    case_id = raw.get("case_id")
    if not isinstance(case_id, str) or not _NAME_RE.fullmatch(case_id):
        raise DynamicCaseError("dynamic case ID is invalid")
    artifact = raw.get("artifact")
    if (
        not isinstance(artifact, dict)
        or not isinstance(artifact.get("publisher"), str)
        or not _NAME_RE.fullmatch(artifact["publisher"])
        or not isinstance(artifact.get("slug"), str)
        or not _NAME_RE.fullmatch(artifact["slug"])
        or not _DIGEST_RE.fullmatch(
            artifact.get("sha256") if isinstance(artifact.get("sha256"), str) else ""
        )
    ):
        raise DynamicCaseError("dynamic case artifact identity is invalid")
    authorization = raw.get("authorization")
    if not isinstance(authorization, dict) or any(
        authorization.get(field) is not False
        for field in (
            "execution_authorized",
            "corpus_authorized",
            "candidate_transfer_authorized",
        )
    ):
        raise DynamicCaseError("dynamic case opens an authorization gate")
    isolation = raw.get("isolation")
    required_isolation = {
        "expected_host": "hanna2",
        "backend": "libvirt-kvm",
        "ephemeral_overlay": True,
        "host_shares": False,
        "host_credentials": False,
        "external_network_interfaces": False,
        "live_egress": False,
        "candidate_transport": "read-only-iso",
        "network_policy": "loopback-sinkhole",
    }
    if not isinstance(isolation, dict) or any(
        isolation.get(key) != expected for key, expected in required_isolation.items()
    ):
        raise DynamicCaseError("dynamic case isolation contract is incomplete")
    if raw.get("selected_entrypoint") is not None:
        raise DynamicCaseError("pre-execution case must not select an entrypoint")
    entrypoints = _entrypoint_records(raw.get("proposed_entrypoints"))
    fixtures = _fixture_records(case_path, raw.get("fixtures"))
    controls = set(
        _string_list(raw.get("required_controls"), label="required controls", maximum=32)
    )
    if not controls >= _REQUIRED_CONTROLS:
        raise DynamicCaseError("dynamic case omits mandatory controls")
    blockers = _string_list(raw.get("blockers"), label="case blockers", maximum=32)
    hypotheses = raw.get("hypotheses")
    hypothesis_ids = (
        [item.get("id") for item in hypotheses if isinstance(item, dict)]
        if isinstance(hypotheses, list)
        else []
    )
    if (
        not isinstance(hypotheses, list)
        or not hypotheses
        or len(hypotheses) > MAX_HYPOTHESES
        or len(hypothesis_ids) != len(set(hypothesis_ids))
        or any(
            not isinstance(item, dict)
            or not isinstance(item.get("id"), str)
            or not _NAME_RE.fullmatch(item["id"])
            or not isinstance(item.get("question"), str)
            or not item["question"]
            for item in hypotheses
        )
    ):
        raise DynamicCaseError("dynamic case hypotheses are invalid")

    artifact_matches = None
    if candidate is not None:
        candidate = _non_symlink_path(candidate, label="candidate")
        result = scan_skill(candidate)
        identity = result.artifact_identity
        artifact_matches = bool(identity and identity.sha256 == artifact["sha256"])
        if not artifact_matches:
            raise DynamicCaseError("candidate does not match the dynamic case artifact")
        artifact_paths = {item.path for item in identity.files}
        if any(item["path"] not in artifact_paths for item in entrypoints):
            raise DynamicCaseError("proposed entrypoint is absent from the candidate artifact")

    return {
        "schema_version": "1.0",
        "case_id": case_id,
        "case_sha256": hashlib.sha256(content).hexdigest(),
        "artifact_sha256": artifact["sha256"],
        "artifact_matches_candidate": artifact_matches,
        "fixtures_verified": fixtures,
        "proposed_entrypoints": entrypoints,
        "blockers": blockers,
        "execution_authorized": False,
        "ready_for_execution": False,
    }
