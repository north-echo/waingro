"""Tests for exfiltration rules."""

from waingro.rules.exfiltration import (
    ClipboardMonitoring,
    CredentialFileAccess,
    EmbeddedCredentialPatterns,
    EnvVariableHarvesting,
    OpenClawWorkspaceScraping,
)


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


def test_exfil_001_dev_configs(make_inline_skill):
    """EXFIL-001 detects access to dev tool config files."""
    skill = make_inline_skill(
        body='GH_TOKEN=$(cat ~/.config/gh/hosts.yml | grep oauth_token)\n'
             'NPM_TOKEN=$(grep "_authToken" ~/.npmrc)'
    )
    findings = CredentialFileAccess().evaluate(skill)
    rule_ids = {f.rule_id for f in findings}
    assert "EXFIL-001" in rule_ids
    matched = {f.matched_content for f in findings}
    assert any("oauth_token" in m or ".config/gh/hosts.yml" in m for m in matched)


def test_exfil_001_authorization_bearer(make_inline_skill):
    """EXFIL-001 detects Authorization: Bearer pattern."""
    skill = make_inline_skill(
        body='grep -i "Authorization: Bearer" /var/log/proxy/access.log'
    )
    findings = CredentialFileAccess().evaluate(skill)
    assert len(findings) >= 1
    assert any("Authorization" in f.matched_content for f in findings)


def test_exfil_004_openclaw_workspace(malicious_credential_exfil):
    rule = OpenClawWorkspaceScraping()
    findings = rule.evaluate(malicious_credential_exfil)
    assert len(findings) >= 1
    assert findings[0].rule_id == "EXFIL-004"


def test_exfil_005_env_grep(make_inline_skill):
    """EXFIL-005 detects environment variable harvesting."""
    skill = make_inline_skill(
        body="env | grep -iE '(key|secret|token|password|aws|api)' > /tmp/.env_dump"
    )
    findings = EnvVariableHarvesting().evaluate(skill)
    assert len(findings) >= 1
    assert findings[0].rule_id == "EXFIL-005"


def test_exfil_005_clean(make_inline_skill):
    """EXFIL-005 does not fire on normal env usage."""
    skill = make_inline_skill(body="echo $HOME\nenv | sort")
    findings = EnvVariableHarvesting().evaluate(skill)
    assert len(findings) == 0


def test_exfil_006_aws_key(make_inline_skill):
    """EXFIL-006 detects AWS access key pattern (AKIA...)."""
    # AKIA followed by 16 uppercase alphanumeric chars
    skill = make_inline_skill(
        body="aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
    )
    findings = EmbeddedCredentialPatterns().evaluate(skill)
    assert len(findings) >= 1
    assert findings[0].rule_id == "EXFIL-006"


def test_exfil_006_github_token(make_inline_skill):
    """EXFIL-006 detects GitHub PAT pattern (ghp_...)."""
    # ghp_ followed by 36 alphanumeric chars
    fake_token = "ghp_" + "A" * 36
    skill = make_inline_skill(body=f"GITHUB_TOKEN={fake_token}")
    findings = EmbeddedCredentialPatterns().evaluate(skill)
    assert len(findings) >= 1
    assert findings[0].rule_id == "EXFIL-006"


def test_exfil_006_clean(make_inline_skill):
    """EXFIL-006 does not fire on normal content."""
    skill = make_inline_skill(body="echo hello\ngit push origin main")
    findings = EmbeddedCredentialPatterns().evaluate(skill)
    assert len(findings) == 0


def test_exfil_007_pbpaste(make_inline_skill):
    """EXFIL-007 detects clipboard access via pbpaste."""
    skill = make_inline_skill(body="CONTENT=$(pbpaste 2>/dev/null)")
    findings = ClipboardMonitoring().evaluate(skill)
    assert len(findings) >= 1
    assert findings[0].rule_id == "EXFIL-007"


def test_exfil_007_clean(make_inline_skill):
    """EXFIL-007 does not fire on normal content."""
    skill = make_inline_skill(body="echo 'hello world'\ncat file.txt")
    findings = ClipboardMonitoring().evaluate(skill)
    assert len(findings) == 0
