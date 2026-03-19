"""Tests for multi-dimensional risk scoring."""

from pathlib import Path

from waingro.analyzers.risk_profile import (
    compute_risk_profile,
    is_scanner_profile,
    verdict_from_profile,
)
from waingro.models import Finding, FindingCategory, Severity


def _f(rule_id: str, sev: Severity = Severity.HIGH,
       cat: FindingCategory = FindingCategory.EXECUTION,
       confidence: float = 1.0) -> Finding:
    f = Finding(
        rule_id=rule_id, title="T", description="D", severity=sev,
        category=cat, file_path=Path("/tmp/t/SKILL.md"),  # noqa: S108
        line_number=1, matched_content="x", remediation="R", reference=None,
    )
    f.confidence = confidence
    return f


def test_c2_skill_high_network_risk():
    findings = [
        _f("NET-002", Severity.CRITICAL, FindingCategory.NETWORK),
        _f("EXEC-001", Severity.CRITICAL, FindingCategory.EXECUTION),
    ]
    profile = compute_risk_profile(findings, security_tool_score=0.0)
    assert profile.network_risk >= 0.15
    assert profile.overall_risk > 0


def test_security_tool_dampened_risk():
    findings = [
        _f("INJECT-002", Severity.CRITICAL, FindingCategory.INJECTION),
        _f("EXEC-001", Severity.CRITICAL, FindingCategory.EXECUTION),
    ]
    high_risk = compute_risk_profile(findings, security_tool_score=0.0)
    low_risk = compute_risk_profile(findings, security_tool_score=0.8)
    assert low_risk.overall_risk < high_risk.overall_risk


def test_low_confidence_findings_reduce_risk():
    full = [_f("EXEC-001", Severity.CRITICAL, confidence=1.0)]
    reduced = [_f("EXEC-001", Severity.CRITICAL, confidence=0.2)]
    p_full = compute_risk_profile(full, 0.0)
    p_reduced = compute_risk_profile(reduced, 0.0)
    assert p_reduced.execution_risk < p_full.execution_risk


def test_scanner_profile_detection():
    findings = [
        _f("EXEC-001", cat=FindingCategory.EXECUTION),
        _f("EXFIL-001", cat=FindingCategory.EXFILTRATION),
        _f("NET-001", cat=FindingCategory.NETWORK),
        _f("INJECT-001", cat=FindingCategory.INJECTION),
        _f("PERSIST-001", cat=FindingCategory.PERSISTENCE),
        _f("OBFUSC-001", Severity.MEDIUM, FindingCategory.OBFUSCATION),
        _f("SOCIAL-001", cat=FindingCategory.SOCIAL_ENGINEERING),
        _f("EXFIL-002", cat=FindingCategory.EXFILTRATION),
    ]
    assert is_scanner_profile(findings) is True


def test_scanner_profile_false_with_c2():
    findings = [
        _f("NET-002", Severity.CRITICAL, FindingCategory.NETWORK),
        _f("EXEC-001", cat=FindingCategory.EXECUTION),
        _f("EXFIL-001", cat=FindingCategory.EXFILTRATION),
        _f("INJECT-001", cat=FindingCategory.INJECTION),
        _f("PERSIST-001", cat=FindingCategory.PERSISTENCE),
        _f("OBFUSC-001", Severity.MEDIUM, FindingCategory.OBFUSCATION),
        _f("SOCIAL-001", cat=FindingCategory.SOCIAL_ENGINEERING),
        _f("EXFIL-002", cat=FindingCategory.EXFILTRATION),
    ]
    assert is_scanner_profile(findings) is False


def test_verdict_malicious_high_network():
    from waingro.analyzers.risk_profile import RiskProfile
    p = RiskProfile(network_risk=0.9, overall_risk=0.5, security_tool_score=0.0)
    assert verdict_from_profile(p) == "MALICIOUS"


def test_verdict_review_high_security_score():
    from waingro.analyzers.risk_profile import RiskProfile
    p = RiskProfile(
        injection_risk=0.8, overall_risk=0.6, security_tool_score=0.7,
    )
    assert verdict_from_profile(p) == "REVIEW"


def test_verdict_clean_no_risk():
    from waingro.analyzers.risk_profile import RiskProfile
    p = RiskProfile()
    assert verdict_from_profile(p) == "CLEAN"


def test_risk_profile_in_scan_result(make_inline_skill):
    """Risk profile is populated in ScanResult after full pipeline."""
    from pathlib import Path

    from waingro.scanner import scan_skill
    fixture = Path(__file__).parent.parent / "fixtures" / "malicious" / "clawhavoc-curl-pipe"
    result = scan_skill(fixture)
    assert result.risk_profile
    assert "execution_risk" in result.risk_profile
    assert "overall_risk" in result.risk_profile
