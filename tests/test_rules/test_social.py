"""Tests for social engineering rules."""

from waingro.rules.social import FakeDependency


def test_social_001_fake_dependency(malicious_fake_dep):
    rule = FakeDependency()
    findings = rule.evaluate(malicious_fake_dep)
    assert len(findings) >= 1
    assert findings[0].rule_id == "SOCIAL-001"
    assert "openclaw-core" in findings[0].remediation


def test_social_001_clean(clean_basic_skill):
    rule = FakeDependency()
    findings = rule.evaluate(clean_basic_skill)
    assert len(findings) == 0
