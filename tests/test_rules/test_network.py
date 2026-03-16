"""Tests for network rules."""

from waingro.rules.network import ReverseShell


def test_net_001_reverse_shell(malicious_reverse_shell):
    rule = ReverseShell()
    findings = rule.evaluate(malicious_reverse_shell)
    assert len(findings) >= 1
    assert findings[0].rule_id == "NET-001"
    assert findings[0].severity.value == "critical"


def test_net_001_clean(clean_basic_skill):
    rule = ReverseShell()
    findings = rule.evaluate(clean_basic_skill)
    assert len(findings) == 0
