"""Tests for the CLI interface."""

import json
from pathlib import Path

from click.testing import CliRunner

from waingro.cli import main

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_version_command():
    runner = CliRunner()
    result = runner.invoke(main, ["version"])
    assert result.exit_code == 0
    assert "0.8.0" in result.output


def test_scan_clean_console():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(FIXTURES_DIR / "clean" / "basic-skill")])
    assert result.exit_code == 0
    assert "CLEAN" in result.output


def test_scan_malicious_console():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(FIXTURES_DIR / "malicious" / "clawhavoc-curl-pipe")])
    assert result.exit_code == 0
    assert "SUSPICIOUS" in result.output


def test_scan_json_output():
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "scan",
            str(FIXTURES_DIR / "malicious" / "clawhavoc-curl-pipe"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["verdict"] == "SUSPICIOUS"
    assert len(data["findings"]) >= 1
    assert data["artifact"]["algorithm"] == "sha256"
    assert data["artifact"]["file_count"] == data["files_scanned"]
    assert data["metadata"]["name"] == "solana-wallet-tracker"


def test_scan_expected_artifact_sha256(tmp_path):
    runner = CliRunner()
    path = FIXTURES_DIR / "clean" / "basic-skill"
    initial = runner.invoke(main, ["scan", str(path), "--format", "json"])
    digest = json.loads(initial.output)["artifact"]["sha256"]

    matched = runner.invoke(main, ["scan", str(path), "--expect-sha256", digest])
    mismatched = runner.invoke(main, ["scan", str(path), "--expect-sha256", "0" * 64])
    invalid = runner.invoke(main, ["scan", str(path), "--expect-sha256", "not-a-digest"])

    assert matched.exit_code == 0
    assert mismatched.exit_code == 1
    assert "artifact SHA-256 mismatch" in mismatched.output
    assert invalid.exit_code == 2
    assert "64 hexadecimal characters" in invalid.output


def test_scan_json_inventories_package_runner_references(tmp_path):
    skill = tmp_path / "package-runner"
    scripts = skill / "scripts"
    scripts.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: package-runner\n---\n", encoding="utf-8")
    (scripts / "run.js").write_text(
        "spawnSync('npx', ['--no-install', 'tsc']);\n"
        "spawnSync('npx', ['degit@2.8.4']);\n"
        "spawnSync('npx', ['prettier']);\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(main, ["scan", str(skill), "--format", "json"])
    report = json.loads(result.output)

    assert result.exit_code == 0
    assert report["package_references"] == [
        {
            "runner": "npx",
            "selector": "tsc",
            "file_path": "scripts/run.js",
            "line_number": 1,
            "immutable": False,
            "network_allowed": False,
        },
        {
            "runner": "npx",
            "selector": "degit@2.8.4",
            "file_path": "scripts/run.js",
            "line_number": 2,
            "immutable": True,
            "network_allowed": True,
        },
        {
            "runner": "npx",
            "selector": "prettier",
            "file_path": "scripts/run.js",
            "line_number": 3,
            "immutable": False,
            "network_allowed": True,
        },
    ]


def test_resolve_packages_uses_metadata_only_client(tmp_path, monkeypatch):
    skill = tmp_path / "resolver"
    scripts = skill / "scripts"
    scripts.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: resolver\n---\n", encoding="utf-8")
    (scripts / "run.js").write_text("spawnSync('npx', ['prettier']);\n", encoding="utf-8")

    def fetch(url):
        assert url == "https://registry.npmjs.org/prettier"
        return {
            "dist-tags": {"latest": "4.0.0"},
            "versions": {
                "4.0.0": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/prettier/-/prettier-4.0.0.tgz",
                        "integrity": "sha512-example",
                    }
                }
            },
        }

    monkeypatch.setattr(
        "waingro.cli.RegistryMetadataClient",
        lambda **_kwargs: fetch,
    )

    result = CliRunner().invoke(main, ["resolve-packages", str(skill)])
    report = json.loads(result.output)

    assert result.exit_code == 0
    assert report["package_resolutions"][0]["resolved_version"] == "4.0.0"
    assert report["package_resolutions"][0]["integrity"] == "sha512-example"


def test_assess_separates_static_capability_from_malicious_intent():
    result = CliRunner().invoke(
        main,
        ["assess", str(FIXTURES_DIR / "malicious" / "clawhavoc-curl-pipe")],
    )
    report = json.loads(result.output)

    assert result.exit_code == 0
    assert report["static_verdict"] == "SUSPICIOUS"
    assert report["verdict"] == "CAPABILITY"
    assert report["assessment"]["dynamic_recommended"] is False
    assert report["assessment"]["dynamic_priority"] == "medium"


def test_dynamic_plan_command_creates_non_authorized_plan(tmp_path):
    output = tmp_path / "plan.json"
    result = CliRunner().invoke(
        main,
        [
            "dynamic",
            "plan",
            str(FIXTURES_DIR / "clean" / "basic-skill"),
            "--base-image",
            "waingro-base.qcow2",
            "--base-image-sha256",
            "a" * 64,
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["execution"]["authorized"] is False
    assert report["execution"]["expected_host"] == "hanna2"
    assert report["execution"]["host_shares"] is False


def test_dynamic_plan_command_records_scenario_contract(tmp_path):
    output = tmp_path / "plan.json"
    result = CliRunner().invoke(
        main,
        [
            "dynamic",
            "plan",
            str(FIXTURES_DIR / "dynamic" / "benign-runtime"),
            "--base-image",
            "waingro-base.qcow2",
            "--base-image-sha256",
            "a" * 64,
            "--host-policy-sha256",
            "d" * 64,
            "--authorize-execution",
            "--interpreter",
            "python",
            "--entrypoint",
            "scripts/run.py",
            "--require-executable",
            "curl",
            "--synthetic-env",
            "SERVICE_TOKEN=token",
            "--require-event",
            "process",
            "--require-exit-zero",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    scenario = json.loads(output.read_text(encoding="utf-8"))["execution"]["scenario"]
    assert scenario["required_executables"] == ["curl", "python3"]
    assert scenario["synthetic_environment"] == {"SERVICE_TOKEN": "token"}
    assert scenario["coverage"]["required_event_types"] == ["process"]


def test_scan_fail_on_critical():
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "scan",
            str(FIXTURES_DIR / "malicious" / "clawhavoc-curl-pipe"),
            "--fail-on",
            "critical",
        ],
    )
    assert result.exit_code == 1


def test_scan_fail_on_clean():
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "scan",
            str(FIXTURES_DIR / "clean" / "basic-skill"),
            "--fail-on",
            "critical",
        ],
    )
    assert result.exit_code == 0


def test_scan_quiet():
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "scan",
            str(FIXTURES_DIR / "malicious" / "clawhavoc-curl-pipe"),
            "--quiet",
        ],
    )
    assert result.exit_code == 0
    assert "SUSPICIOUS" in result.output
    # Quiet should be short
    assert len(result.output.strip().split("\n")) <= 3


def test_audit_command():
    runner = CliRunner()
    result = runner.invoke(main, ["audit", str(FIXTURES_DIR / "malicious")])
    assert result.exit_code == 0
    assert "skills" in result.output.lower() or "MALICIOUS" in result.output


def test_audit_json():
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "audit",
            str(FIXTURES_DIR / "malicious"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "skills" in data
    assert len(data["skills"]) >= 5


def test_scan_console_output_file(tmp_path):
    runner = CliRunner()
    output = tmp_path / "scan.txt"
    result = runner.invoke(
        main,
        [
            "scan",
            str(FIXTURES_DIR / "clean" / "basic-skill"),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0
    assert result.output == ""
    assert "VERDICT: CLEAN" in output.read_text(encoding="utf-8")


def test_scan_directory_without_skill_manifest_is_a_cli_error(tmp_path):
    result = CliRunner().invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "SKILL.md not found" in result.output
    assert "Traceback" not in result.output


def test_audit_console_output_file(tmp_path):
    runner = CliRunner()
    output = tmp_path / "audit.txt"
    result = runner.invoke(
        main,
        [
            "audit",
            str(FIXTURES_DIR / "clean"),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0
    assert result.output == ""
    assert "Auditing 1 skills" in output.read_text(encoding="utf-8")


def test_severity_filter_does_not_change_verdict_or_fail_on(tmp_path):
    skill = tmp_path / "scheduled-task"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: scheduled-task\n---\nRun: @reboot ~/.local/bin/agent.sh\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "scan",
            str(skill),
            "--format",
            "json",
            "--severity",
            "critical",
            "--fail-on",
            "high",
        ],
    )
    assert result.exit_code == 1
    report = json.loads(result.output)
    assert report["verdict"] == "SUSPICIOUS"
    assert report["findings"] == []


def test_semantic_analysis_receives_bundled_files_and_refreshes_risk(tmp_path, monkeypatch):
    skill = tmp_path / "audit-scanner"
    scripts = skill / "scripts"
    scripts.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: audit-scanner\n---\nReview code.\n", encoding="utf-8"
    )
    (scripts / "check.py").write_text("eval(payload)\n", encoding="utf-8")

    class FakeSemanticAnalyzer:
        def __init__(self, budget):
            assert budget == 5.0

        def should_analyze(self, _verdict, _score):
            return True

        def analyze(self, parsed, _findings):
            assert any(file.path.name == "check.py" for file in parsed.bundled_content)
            return {"skill_classification": "security_tool", "findings": []}

        def apply_results(self, findings, _result):
            for finding in findings:
                finding.confidence = 0.1
            return findings

    monkeypatch.setattr("waingro.analyzers.semantic.SemanticAnalyzer", FakeSemanticAnalyzer)
    result = CliRunner().invoke(main, ["scan", str(skill), "--semantic", "--format", "json"])
    assert result.exit_code == 0
    report = json.loads(result.output)
    assert report["verdict"] == "REVIEW"
    assert report["risk_profile"]["execution_risk"] == 0.014
