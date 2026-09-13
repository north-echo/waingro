"""Tests for the non-authorizing hanna2 containment control catalog."""

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from waingro.cli import main
from waingro.dynamic.controls import (
    REQUIRED_CONTROL_IDS,
    DynamicControlError,
    validate_control_suite,
)

SUITE = Path(__file__).parents[1] / "deploy" / "hanna2" / "control-suite.json"


def _copy_suite(tmp_path: Path) -> tuple[Path, dict]:
    raw = json.loads(SUITE.read_text(encoding="utf-8"))
    shutil.copytree(SUITE.parent / "control-fixtures", tmp_path / "control-fixtures")
    path = tmp_path / "control-suite.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path, raw


def test_packaged_control_suite_is_complete_and_never_authorizes_execution():
    report = validate_control_suite(SUITE)

    assert {item["id"] for item in report["controls_verified"]} >= REQUIRED_CONTROL_IDS
    assert report["execution_authorized"] is False
    assert report["transfer_authorized"] is False
    assert report["ready_for_execution"] is False
    assert sum(item["fixture"] is not None for item in report["controls_verified"]) == 6


def test_check_controls_cli_is_read_only():
    result = CliRunner().invoke(main, ["dynamic", "check-controls", str(SUITE)])

    assert result.exit_code == 0
    assert json.loads(result.output)["ready_for_execution"] is False


def test_control_suite_rejects_any_open_authorization_gate(tmp_path):
    path, raw = _copy_suite(tmp_path)
    raw["authorization"]["execution_authorized"] = True
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(DynamicControlError, match="authorization gate"):
        validate_control_suite(path)


def test_control_suite_rejects_missing_mandatory_control(tmp_path):
    path, raw = _copy_suite(tmp_path)
    raw["controls"] = [item for item in raw["controls"] if item["id"] != "tampered-image"]
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(DynamicControlError, match="omits mandatory controls"):
        validate_control_suite(path)


def test_control_suite_rejects_a_relabelled_mandatory_outcome(tmp_path):
    path, raw = _copy_suite(tmp_path)
    next(item for item in raw["controls"] if item["id"] == "timeout")["expected"] = "exit-0"
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(DynamicControlError, match="mandatory control contract mismatch"):
        validate_control_suite(path)


def test_control_suite_rejects_fixture_digest_tampering(tmp_path):
    raw = json.loads(SUITE.read_text(encoding="utf-8"))
    control_root = tmp_path / "control-fixtures" / "benign-canary"
    control_root.mkdir(parents=True)
    (control_root / "SKILL.md").write_text("---\nname: changed\n---\n", encoding="utf-8")
    raw["controls"] = [raw["controls"][1]]
    raw["controls"][0]["id"] = "benign-canary"
    path = tmp_path / "control-suite.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(DynamicControlError, match="fixture SHA-256 mismatch"):
        validate_control_suite(path)
