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
    assert "MALICIOUS" in result.output


def test_scan_json_output():
    runner = CliRunner()
    result = runner.invoke(main, [
        "scan",
        str(FIXTURES_DIR / "malicious" / "clawhavoc-curl-pipe"),
        "--format", "json",
    ])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["verdict"] == "MALICIOUS"
    assert len(data["findings"]) >= 1


def test_scan_fail_on_critical():
    runner = CliRunner()
    result = runner.invoke(main, [
        "scan",
        str(FIXTURES_DIR / "malicious" / "clawhavoc-curl-pipe"),
        "--fail-on", "critical",
    ])
    assert result.exit_code == 1


def test_scan_fail_on_clean():
    runner = CliRunner()
    result = runner.invoke(main, [
        "scan",
        str(FIXTURES_DIR / "clean" / "basic-skill"),
        "--fail-on", "critical",
    ])
    assert result.exit_code == 0


def test_scan_quiet():
    runner = CliRunner()
    result = runner.invoke(main, [
        "scan",
        str(FIXTURES_DIR / "malicious" / "clawhavoc-curl-pipe"),
        "--quiet",
    ])
    assert result.exit_code == 0
    assert "MALICIOUS" in result.output
    # Quiet should be short
    assert len(result.output.strip().split("\n")) <= 3


def test_audit_command():
    runner = CliRunner()
    result = runner.invoke(main, ["audit", str(FIXTURES_DIR / "malicious")])
    assert result.exit_code == 0
    assert "skills" in result.output.lower() or "MALICIOUS" in result.output


def test_audit_json():
    runner = CliRunner()
    result = runner.invoke(main, [
        "audit",
        str(FIXTURES_DIR / "malicious"),
        "--format", "json",
    ])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "skills" in data
    assert len(data["skills"]) >= 5
