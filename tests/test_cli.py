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
    assert "0.4.0" in result.output


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
