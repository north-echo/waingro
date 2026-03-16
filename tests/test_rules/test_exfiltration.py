"""Tests for exfiltration rules."""

from waingro.rules.exfiltration import CredentialFileAccess, OpenClawWorkspaceScraping


def test_exfil_001_credential_files(malicious_credential_exfil):
    rule = CredentialFileAccess()
    findings = rule.evaluate(malicious_credential_exfil)
    assert len(findings) >= 1
    rule_ids = {f.rule_id for f in findings}
    assert "EXFIL-001" in rule_ids


def test_exfil_001_clean(clean_basic_skill):
    rule = CredentialFileAccess()
    findings = rule.evaluate(clean_basic_skill)
    assert len(findings) == 0


def test_exfil_004_openclaw_workspace(malicious_credential_exfil):
    rule = OpenClawWorkspaceScraping()
    findings = rule.evaluate(malicious_credential_exfil)
    assert len(findings) >= 1
    assert findings[0].rule_id == "EXFIL-004"
