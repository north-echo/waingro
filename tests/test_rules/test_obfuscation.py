"""Tests for obfuscation rules."""

from waingro.rules.obfuscation import Base64Strings, StringConcatenation


def test_obfusc_001_base64_strings(malicious_base64):
    rule = Base64Strings()
    findings = rule.evaluate(malicious_base64)
    assert len(findings) >= 1
    assert findings[0].rule_id == "OBFUSC-001"


def test_obfusc_001_clean(clean_basic_skill):
    rule = Base64Strings()
    findings = rule.evaluate(clean_basic_skill)
    assert len(findings) == 0


def test_obfusc_002_variable_concat(make_inline_skill):
    """OBFUSC-002 detects ${VAR}${VAR} concatenation patterns."""
    skill = make_inline_skill(body="${CMD1}${CMD2} ${TARGET}${DOMAIN}")
    findings = StringConcatenation().evaluate(skill)
    assert len(findings) >= 1
    assert findings[0].rule_id == "OBFUSC-002"


def test_obfusc_002_chr_concat(make_inline_skill):
    """OBFUSC-002 detects chr() concatenation to build strings."""
    skill = make_inline_skill(body="c = chr(99) + chr(117) + chr(114) + chr(108)")
    findings = StringConcatenation().evaluate(skill)
    assert len(findings) >= 1
    assert findings[0].rule_id == "OBFUSC-002"


def test_obfusc_002_echo_subshell(make_inline_skill):
    """OBFUSC-002 detects $(echo X) subshell command construction."""
    skill = make_inline_skill(body="$( echo bash )")
    findings = StringConcatenation().evaluate(skill)
    assert len(findings) >= 1
    assert findings[0].rule_id == "OBFUSC-002"


def test_obfusc_002_clean(make_inline_skill):
    """OBFUSC-002 does not fire on normal variable usage."""
    skill = make_inline_skill(body="echo $HOME\nexport PATH=$PATH:/usr/local/bin")
    findings = StringConcatenation().evaluate(skill)
    assert len(findings) == 0
