"""Validate the benign, non-authorizing hanna2 containment control catalog."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath

from waingro.parsers.script import read_file_bytes
from waingro.scanner import scan_skill

MAX_CONTROL_SUITE_BYTES = 256 * 1024
MAX_CONTROLS = 64
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_STAGES = frozenset({"guest", "host-preflight", "runner-rejection", "host-postflight"})
_EXPECTED = frozenset(
    {
        "exit-0",
        "timeout",
        "resource-limit",
        "policy-rejection",
        "posture-match",
        "cleanup-complete",
        "trusted-trace-rejection",
    }
)
_CONTROL_CONTRACTS = {
    "posture-before": ("host-preflight", "posture-match", False),
    "benign-canary": ("guest", "exit-0", True),
    "negative-control": ("guest", "exit-0", True),
    "network-sinkhole": ("guest", "exit-0", True),
    "shim-interception": ("guest", "exit-0", True),
    "timeout": ("guest", "timeout", True),
    "output-volume": ("guest", "resource-limit", True),
    "resource-policy": ("runner-rejection", "policy-rejection", False),
    "missing-executable": ("runner-rejection", "policy-rejection", False),
    "tampered-plan": ("runner-rejection", "policy-rejection", False),
    "tampered-image": ("runner-rejection", "policy-rejection", False),
    "trace-trust-rejection": ("runner-rejection", "trusted-trace-rejection", False),
    "posture-after": ("host-postflight", "posture-match", False),
    "destroy-guest": ("host-postflight", "cleanup-complete", False),
}
REQUIRED_CONTROL_IDS = frozenset(_CONTROL_CONTRACTS)


class DynamicControlError(ValueError):
    """A containment control suite violates the non-execution contract."""


def _non_symlink_path(path: Path, *, label: str) -> Path:
    absolute = path.absolute()
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise DynamicControlError(f"{label} could not be resolved safely") from exc
    if absolute != resolved:
        raise DynamicControlError(f"{label} path must not traverse a symlink")
    return absolute


def _load_object(path: Path) -> tuple[dict, bytes]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_CONTROL_SUITE_BYTES:
        raise DynamicControlError("control suite must be a bounded, non-symlink JSON file")
    try:
        content = read_file_bytes(path)
        raw = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DynamicControlError("control suite is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise DynamicControlError("control suite root is not an object")
    return raw, content


def _fixture_path(suite_path: Path, value: object) -> Path:
    if not isinstance(value, str):
        raise DynamicControlError("control fixture path is invalid")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or not 2 <= len(relative.parts) <= 3
        or any(not re.fullmatch(r"[A-Za-z0-9._-]+", part) for part in relative.parts)
    ):
        raise DynamicControlError("control fixture path violates policy")
    fixture = _non_symlink_path(suite_path.parent / value, label="control fixture")
    if not fixture.is_dir() or not (fixture / "SKILL.md").is_file():
        raise DynamicControlError("control fixture must be a skill directory")
    return fixture


def validate_control_suite(suite_path: Path) -> dict:
    """Verify the benign control catalog without creating plans or running fixtures."""
    suite_path = _non_symlink_path(suite_path, label="control suite")
    raw, content = _load_object(suite_path)
    if (
        set(raw)
        != {
            "schema_version",
            "suite_id",
            "authorization",
            "expected_host",
            "controls",
            "blockers",
        }
        or raw.get("schema_version") != "1.0"
    ):
        raise DynamicControlError("unsupported or malformed control-suite schema")
    suite_id = raw.get("suite_id")
    if not isinstance(suite_id, str) or not _NAME_RE.fullmatch(suite_id):
        raise DynamicControlError("control suite ID is invalid")
    authorization = raw.get("authorization")
    if (
        not isinstance(authorization, dict)
        or set(authorization)
        != {
            "execution_authorized",
            "transfer_authorized",
        }
        or any(value is not False for value in authorization.values())
    ):
        raise DynamicControlError("control suite opens an authorization gate")
    if raw.get("expected_host") != "hanna2":
        raise DynamicControlError("control suite is not bound to hanna2")
    blockers = raw.get("blockers")
    if (
        not isinstance(blockers, list)
        or not blockers
        or any(not isinstance(item, str) or not item or len(item) > 2000 for item in blockers)
    ):
        raise DynamicControlError("control suite must retain unresolved blockers")
    controls = raw.get("controls")
    if not isinstance(controls, list) or not controls or len(controls) > MAX_CONTROLS:
        raise DynamicControlError("control records are invalid")

    seen: set[str] = set()
    verified = []
    for control in controls:
        if not isinstance(control, dict) or set(control) != {
            "id",
            "stage",
            "fixture",
            "fixture_sha256",
            "expected",
            "execution_authorized",
        }:
            raise DynamicControlError("control record is malformed")
        control_id = control.get("id")
        stage = control.get("stage")
        expected = control.get("expected")
        if (
            not isinstance(control_id, str)
            or not _NAME_RE.fullmatch(control_id)
            or control_id in seen
            or stage not in _STAGES
            or expected not in _EXPECTED
            or control.get("execution_authorized") is not False
        ):
            raise DynamicControlError("control record violates policy")
        seen.add(control_id)
        fixture_value = control.get("fixture")
        expected_digest = control.get("fixture_sha256")
        required_contract = _CONTROL_CONTRACTS.get(control_id)
        if required_contract is not None and (stage, expected, fixture_value is not None) != (
            required_contract
        ):
            raise DynamicControlError(f"mandatory control contract mismatch: {control_id}")
        observed_digest = None
        if fixture_value is None:
            if expected_digest is not None or stage == "guest":
                raise DynamicControlError("control fixture identity is incomplete")
        else:
            if (
                stage != "guest"
                or not isinstance(expected_digest, str)
                or not _DIGEST_RE.fullmatch(expected_digest)
            ):
                raise DynamicControlError("control fixture identity is incomplete")
            fixture = _fixture_path(suite_path, fixture_value)
            result = scan_skill(fixture)
            if result.artifact_identity is None:
                raise DynamicControlError("control fixture has no artifact identity")
            observed_digest = result.artifact_identity.sha256
            if observed_digest != expected_digest:
                raise DynamicControlError(f"control fixture SHA-256 mismatch: {control_id}")
        verified.append(
            {
                "id": control_id,
                "stage": stage,
                "expected": expected,
                "fixture": fixture_value,
                "fixture_sha256": observed_digest,
                "execution_authorized": False,
            }
        )

    missing = sorted(REQUIRED_CONTROL_IDS - seen)
    if missing:
        raise DynamicControlError(f"control suite omits mandatory controls: {', '.join(missing)}")
    return {
        "schema_version": "1.0",
        "suite_id": suite_id,
        "suite_sha256": hashlib.sha256(content).hexdigest(),
        "expected_host": "hanna2",
        "controls_verified": verified,
        "blockers": blockers,
        "execution_authorized": False,
        "transfer_authorized": False,
        "ready_for_execution": False,
    }
