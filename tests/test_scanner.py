"""Integration tests for the scanner."""

from pathlib import Path

from waingro.scanner import audit_skills, scan_skill

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_scan_clean_skill():
    result = scan_skill(FIXTURES_DIR / "clean" / "basic-skill")
    assert result.verdict == "CLEAN"
    assert result.files_scanned >= 1
    assert result.rules_evaluated > 0


def test_scan_curl_pipe():
    result = scan_skill(FIXTURES_DIR / "malicious" / "clawhavoc-curl-pipe")
    assert result.verdict == "MALICIOUS"
    rule_ids = {f.rule_id for f in result.findings}
    assert "EXEC-001" in rule_ids


def test_scan_base64():
    result = scan_skill(FIXTURES_DIR / "malicious" / "clawhavoc-base64")
    assert result.verdict == "MALICIOUS"
    rule_ids = {f.rule_id for f in result.findings}
    assert "EXEC-002" in rule_ids


def test_scan_reverse_shell():
    result = scan_skill(FIXTURES_DIR / "malicious" / "authtool-reverse-shell")
    assert result.verdict == "MALICIOUS"
    rule_ids = {f.rule_id for f in result.findings}
    assert "NET-001" in rule_ids


def test_scan_credential_exfil():
    result = scan_skill(FIXTURES_DIR / "malicious" / "credential-exfil")
    assert result.verdict in ("MALICIOUS", "SUSPICIOUS")
    rule_ids = {f.rule_id for f in result.findings}
    assert "EXFIL-001" in rule_ids or "EXFIL-004" in rule_ids


def test_scan_persistence():
    result = scan_skill(FIXTURES_DIR / "malicious" / "persistence-crontab")
    assert result.verdict in ("MALICIOUS", "SUSPICIOUS")
    rule_ids = {f.rule_id for f in result.findings}
    assert "PERSIST-001" in rule_ids or "EXEC-001" in rule_ids


def test_scan_fake_dependency():
    result = scan_skill(FIXTURES_DIR / "malicious" / "fake-dependency")
    assert result.verdict in ("MALICIOUS", "SUSPICIOUS")
    rule_ids = {f.rule_id for f in result.findings}
    assert "SOCIAL-001" in rule_ids


def test_audit_malicious_dir():
    results = audit_skills(FIXTURES_DIR / "malicious")
    assert len(results) >= 5
    verdicts = {r.verdict for r in results}
    assert "MALICIOUS" in verdicts or "SUSPICIOUS" in verdicts
