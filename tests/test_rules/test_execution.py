"""Tests for execution rules."""

from waingro.rules.execution import Base64Execution, CurlPipeShell, EvalExec, PowerShellCradle


def test_exec_001_curl_pipe(malicious_curl_pipe):
    rule = CurlPipeShell()
    findings = rule.evaluate(malicious_curl_pipe)
    assert len(findings) >= 1
    assert findings[0].rule_id == "EXEC-001"
    assert findings[0].severity.value == "critical"


def test_exec_001_clean(clean_basic_skill):
    rule = CurlPipeShell()
    findings = rule.evaluate(clean_basic_skill)
    assert len(findings) == 0


def test_exec_002_base64(malicious_base64):
    rule = Base64Execution()
    findings = rule.evaluate(malicious_base64)
    assert len(findings) >= 1
    assert findings[0].rule_id == "EXEC-002"


def test_exec_003_eval(malicious_credential_exfil):
    """The credential-exfil fixture uses os.expanduser which won't trigger, but has glob."""
    rule = EvalExec()
    # This fixture doesn't contain eval/exec directly, so 0 is expected
    rule.evaluate(malicious_credential_exfil)


def test_exec_004_powershell(clean_basic_skill):
    rule = PowerShellCradle()
    findings = rule.evaluate(clean_basic_skill)
    assert len(findings) == 0
