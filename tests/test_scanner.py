"""Integration tests for the scanner."""

from pathlib import Path

from waingro.scanner import DEFAULT_KNOWN_GOOD, audit_skills, load_skill, scan_skill

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_scan_clean_skill():
    result = scan_skill(FIXTURES_DIR / "clean" / "basic-skill")
    assert result.verdict == "CLEAN"
    assert result.files_scanned >= 1
    assert result.rules_evaluated > 0


def test_packaged_known_skill_baseline_exists():
    assert DEFAULT_KNOWN_GOOD.is_file()
    assert "weather-check" in DEFAULT_KNOWN_GOOD.read_text(encoding="utf-8")


def test_load_skill_includes_bundled_content():
    skill = load_skill(CORPUS_DIR / "benign" / "bundled-subprocess")
    assert any(file.path.name == "lint.py" for file in skill.bundled_content)


def test_scan_curl_pipe():
    result = scan_skill(FIXTURES_DIR / "malicious" / "clawhavoc-curl-pipe")
    assert result.verdict == "SUSPICIOUS"
    rule_ids = {f.rule_id for f in result.findings}
    assert "EXEC-001" in rule_ids


def test_scan_base64():
    result = scan_skill(FIXTURES_DIR / "malicious" / "clawhavoc-base64")
    assert result.verdict == "MALICIOUS"
    rule_ids = {f.rule_id for f in result.findings}
    assert "EXEC-002" in rule_ids


def test_scan_reverse_shell():
    result = scan_skill(FIXTURES_DIR / "malicious" / "authtool-reverse-shell")
    assert result.verdict == "SUSPICIOUS"
    rule_ids = {f.rule_id for f in result.findings}
    assert "NET-001" in rule_ids


def test_scan_credential_exfil():
    result = scan_skill(FIXTURES_DIR / "malicious" / "credential-exfil")
    # This fixture collects sensitive files but contains no egress sink. The
    # primitive remains visible without being mislabeled as exfiltration.
    assert result.verdict == "WARNING"
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


# --- Bundled content integration tests ---

CORPUS_DIR = FIXTURES_DIR / "skills"


def test_scan_c2_beacon_bundled():
    """c2-beacon: eval in monitor.sh detected through full pipeline."""
    result = scan_skill(CORPUS_DIR / "clawhavoc" / "c2-beacon")
    assert result.verdict != "CLEAN"
    assert result.files_scanned >= 2
    rule_ids = {f.rule_id for f in result.findings}
    assert "EXEC-003" in rule_ids  # eval "$RESP" in monitor.sh


def test_scan_npm_preinstall_hook_bundled():
    """npm-preinstall-hook: hooks in package.json detected through full pipeline."""
    result = scan_skill(CORPUS_DIR / "supply-chain" / "npm-preinstall-hook")
    assert result.verdict != "CLEAN"
    assert result.files_scanned >= 2
    rule_ids = {f.rule_id for f in result.findings}
    assert "SOCIAL-003" in rule_ids or "EXEC-001" in rule_ids


def test_scan_dns_exfil_bundled():
    """dns-exfil: dig in dns_test.sh detected through full pipeline."""
    result = scan_skill(CORPUS_DIR / "data-exfiltration" / "dns-exfil")
    assert result.verdict != "CLEAN"
    assert result.files_scanned >= 2
    rule_ids = {f.rule_id for f in result.findings}
    assert "NET-004" in rule_ids
