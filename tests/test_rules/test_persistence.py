"""Tests for persistence rules."""

from waingro.rules.persistence import CrontabModification


def test_persist_001_crontab(malicious_persistence):
    rule = CrontabModification()
    findings = rule.evaluate(malicious_persistence)
    assert len(findings) >= 1
    assert findings[0].rule_id == "PERSIST-001"


def test_persist_001_clean(clean_basic_skill):
    rule = CrontabModification()
    findings = rule.evaluate(clean_basic_skill)
    assert len(findings) == 0


def test_persist_001_reboot(make_inline_skill):
    """PERSIST-001 detects @reboot crontab entries."""
    skill = make_inline_skill(body='(crontab -l; echo "@reboot ~/.local/bin/agent.sh") | crontab -')
    findings = CrontabModification().evaluate(skill)
    assert len(findings) >= 1
    assert findings[0].rule_id == "PERSIST-001"
    matched_all = " ".join(f.matched_content for f in findings)
    assert "@reboot" in matched_all or "crontab" in matched_all
