"""Tests for non-executing dynamic case dossiers."""

import hashlib
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from waingro.cli import main
from waingro.dynamic.case import DynamicCaseError, validate_dynamic_case
from waingro.scanner import scan_skill

PACKAGED_CASE = (
    Path(__file__).parents[1] / "deploy" / "hanna2" / "cases" / "clawgrid-connector" / "case.json"
)


def _case(tmp_path, artifact_sha256):
    fixture = tmp_path / "response.json"
    fixture.write_text('{"status":"synthetic"}\n', encoding="utf-8")
    fixture_sha256 = hashlib.sha256(fixture.read_bytes()).hexdigest()
    case = {
        "schema_version": "1.0",
        "case_id": "test-case",
        "artifact": {
            "publisher": "test-publisher",
            "slug": "test-skill",
            "sha256": artifact_sha256,
        },
        "authorization": {
            "execution_authorized": False,
            "corpus_authorized": False,
            "candidate_transfer_authorized": False,
        },
        "isolation": {
            "expected_host": "hanna2",
            "backend": "libvirt-kvm",
            "ephemeral_overlay": True,
            "host_shares": False,
            "host_credentials": False,
            "external_network_interfaces": False,
            "live_egress": False,
            "candidate_transport": "read-only-iso",
            "network_policy": "loopback-sinkhole",
        },
        "selected_entrypoint": None,
        "proposed_entrypoints": [
            {"path": "scripts/run.py", "interpreter": "python", "execute": False}
        ],
        "fixtures": [
            {
                "path": "response.json",
                "sha256": fixture_sha256,
                "purpose": "Synthetic test response",
            }
        ],
        "containment_profile": {
            "openclaw_skill_slug": "test-skill",
            "inert_command_shims": ["openclaw", "crontab"],
            "sinkhole_http_response": {
                "host": "fixture.invalid",
                "method": "POST",
                "path": "/api/test",
                "fixture": "response.json",
            },
            "synthetic_json_files": [
                {"home_path": ".fixture/config.json", "fixture": "response.json"}
            ],
        },
        "hypotheses": [{"id": "test-hypothesis", "question": "What happens?"}],
        "required_controls": [
            "benign-canary",
            "negative-control",
            "posture-before",
            "posture-after",
            "destroy-guest",
        ],
        "blockers": ["Execution is not authorized."],
    }
    path = tmp_path / "case.json"
    path.write_text(json.dumps(case), encoding="utf-8")
    return path, case


def test_packaged_clawgrid_case_is_valid_and_not_runnable():
    report = validate_dynamic_case(PACKAGED_CASE)

    assert report["artifact_sha256"] == (
        "fe043bf2f62c0193ff4619149b7952abdee6b208551b81c6ca38ab407f7c24c1"
    )
    assert report["execution_authorized"] is False
    assert report["ready_for_execution"] is False
    assert report["artifact_matches_candidate"] is None
    assert report["fixtures_verified"][0]["size_bytes"] == 704
    assert report["fixtures_verified"][1]["size_bytes"] == 161
    assert report["containment_profile"]["inert_command_shims"] == ["openclaw", "crontab"]


def test_case_can_be_bound_to_an_exact_candidate_without_execution(tmp_path):
    candidate = tmp_path / "candidate"
    scripts = candidate / "scripts"
    scripts.mkdir(parents=True)
    (candidate / "SKILL.md").write_text("---\nname: case-test\n---\n", encoding="utf-8")
    (scripts / "run.py").write_text("print('fixture')\n", encoding="utf-8")
    identity = scan_skill(candidate).artifact_identity
    assert identity is not None
    path, _raw = _case(tmp_path, identity.sha256)

    report = validate_dynamic_case(path, candidate)

    assert report["artifact_matches_candidate"] is True
    assert report["ready_for_execution"] is False


def test_case_rejects_any_open_authorization_gate(tmp_path):
    path, raw = _case(tmp_path, "a" * 64)
    raw["authorization"]["execution_authorized"] = True
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(DynamicCaseError, match="authorization gate"):
        validate_dynamic_case(path)


def test_case_rejects_tampered_fixture(tmp_path):
    path, _raw = _case(tmp_path, "a" * 64)
    (tmp_path / "response.json").write_text('{"status":"changed"}\n', encoding="utf-8")

    with pytest.raises(DynamicCaseError, match="fixture SHA-256 mismatch"):
        validate_dynamic_case(path)


def test_case_rejects_selected_entrypoint(tmp_path):
    path, raw = _case(tmp_path, "a" * 64)
    raw["selected_entrypoint"] = "scripts/run.py"
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(DynamicCaseError, match="must not select"):
        validate_dynamic_case(path)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda raw: raw["containment_profile"]["inert_command_shims"].append("curl"),
            "shim set",
        ),
        (
            lambda raw: raw["containment_profile"]["sinkhole_http_response"].update(
                {"fixture": "missing.json"}
            ),
            "sinkhole response profile",
        ),
        (
            lambda raw: raw["containment_profile"]["sinkhole_http_response"].update(
                {"method": "post"}
            ),
            "sinkhole response profile",
        ),
        (
            lambda raw: raw["containment_profile"]["synthetic_json_files"][0].update(
                {"home_path": ".ssh/config.json"}
            ),
            "home path",
        ),
        (
            lambda raw: raw["containment_profile"]["synthetic_json_files"][0].update(
                {"fixture": "missing.json"}
            ),
            "synthetic JSON profile",
        ),
    ],
)
def test_case_rejects_unsafe_containment_profile(tmp_path, mutation, message):
    path, raw = _case(tmp_path, "a" * 64)
    mutation(raw)
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(DynamicCaseError, match=message):
        validate_dynamic_case(path)


def test_case_rejects_fixture_reached_through_symlinked_directory(tmp_path):
    path, raw = _case(tmp_path, "a" * 64)
    fixture_directory = tmp_path / "fixtures"
    fixture_directory.mkdir()
    target_directory = tmp_path / "target"
    target_directory.mkdir()
    target = target_directory / "response.json"
    target.write_text('{"status":"synthetic"}\n', encoding="utf-8")
    fixture_directory.rmdir()
    fixture_directory.symlink_to(target_directory, target_is_directory=True)
    raw["fixtures"] = [
        {
            "path": "fixtures/response.json",
            "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            "purpose": "Synthetic test response",
        }
    ]
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(DynamicCaseError, match="must not traverse a symlink"):
        validate_dynamic_case(path)


def test_check_case_cli_is_read_only():
    result = CliRunner().invoke(main, ["dynamic", "check-case", str(PACKAGED_CASE)])

    assert result.exit_code == 0
    assert json.loads(result.output)["ready_for_execution"] is False
