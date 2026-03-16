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
