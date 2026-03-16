"""Tests for obfuscation rules."""

from waingro.rules.obfuscation import Base64Strings


def test_obfusc_001_base64_strings(malicious_base64):
    rule = Base64Strings()
    findings = rule.evaluate(malicious_base64)
    assert len(findings) >= 1
    assert findings[0].rule_id == "OBFUSC-001"


def test_obfusc_001_clean(clean_basic_skill):
    rule = Base64Strings()
    findings = rule.evaluate(clean_basic_skill)
    assert len(findings) == 0
