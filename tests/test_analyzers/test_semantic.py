"""Tests for Claude API semantic analysis (Layer 4) — mocked, no real API calls."""

from pathlib import Path

from waingro.analyzers.semantic import SemanticAnalyzer
from waingro.models import Finding, FindingCategory, Severity


def _f(rule_id: str, sev: Severity = Severity.HIGH,
       cat: FindingCategory = FindingCategory.INJECTION) -> Finding:
    return Finding(
        rule_id=rule_id, title="T", description="D", severity=sev,
        category=cat, file_path=Path("/tmp/t/SKILL.md"),  # noqa: S108
        line_number=1, matched_content="test", remediation="R", reference=None,
    )


def test_should_analyze_review_verdict():
    a = SemanticAnalyzer(api_key="fake")
    assert a.should_analyze("REVIEW", 0.5) is True


def test_should_not_analyze_malicious():
    a = SemanticAnalyzer(api_key="fake")
    assert a.should_analyze("MALICIOUS", 0.1) is False


def test_should_not_analyze_clean():
    a = SemanticAnalyzer(api_key="fake")
    assert a.should_analyze("CLEAN", 0.0) is False


def test_should_not_analyze_high_security_score():
    a = SemanticAnalyzer(api_key="fake")
    assert a.should_analyze("REVIEW", 0.9) is False


def test_should_not_analyze_low_security_score():
    a = SemanticAnalyzer(api_key="fake")
    assert a.should_analyze("SUSPICIOUS", 0.1) is False


def test_should_not_analyze_over_budget():
    a = SemanticAnalyzer(api_key="fake", budget=0.0)
    assert a.should_analyze("REVIEW", 0.5) is False


def test_apply_security_tool_result():
    a = SemanticAnalyzer(api_key="fake")
    findings = [_f("INJECT-002"), _f("EXEC-001", cat=FindingCategory.EXECUTION)]
    result = {
        "skill_classification": "security_tool",
        "findings": [
            {"rule_id": "INJECT-002", "context": "detection", "reasoning": "test"},
            {"rule_id": "EXEC-001", "context": "detection", "reasoning": "test"},
        ],
    }
    adjusted = a.apply_results(findings, result)
    assert all(f.confidence == 0.1 for f in adjusted)
    assert all("Semantic analysis" in (f.context_note or "") for f in adjusted)


def test_apply_malicious_result():
    a = SemanticAnalyzer(api_key="fake")
    findings = [_f("EXEC-001", cat=FindingCategory.EXECUTION)]
    findings[0].confidence = 0.3  # was reduced by Layer 1
    result = {
        "skill_classification": "malicious",
        "findings": [
            {"rule_id": "EXEC-001", "context": "execution", "reasoning": "real attack"},
        ],
    }
    adjusted = a.apply_results(findings, result)
    assert adjusted[0].confidence == 1.0


def test_apply_never_adjusts_net002():
    a = SemanticAnalyzer(api_key="fake")
    findings = [_f("NET-002", Severity.CRITICAL, FindingCategory.NETWORK)]
    result = {"skill_classification": "security_tool", "findings": []}
    adjusted = a.apply_results(findings, result)
    assert adjusted[0].confidence == 1.0  # Unchanged


def test_normalize_tool_use_security_tool():
    """Tool use result with is_security_tool=True normalizes correctly."""
    a = SemanticAnalyzer(api_key="fake")
    result = a._normalize_result({
        "verdict": "REVIEW",
        "confidence": 0.9,
        "is_security_tool": True,
        "reasoning": "Detection signatures in blocked patterns section",
        "findings": [
            {"pattern": "INJECT-002", "intent": "defensive"},
        ],
    })
    assert result["skill_classification"] == "security_tool"
    assert result["confidence"] == 0.9
    assert result["findings"][0]["context"] == "detection"


def test_normalize_tool_use_malicious():
    """Tool use result with MALICIOUS verdict normalizes correctly."""
    a = SemanticAnalyzer(api_key="fake")
    result = a._normalize_result({
        "verdict": "MALICIOUS",
        "confidence": 0.95,
        "is_security_tool": False,
        "reasoning": "Hidden os.system call with C2 IP",
        "findings": [
            {"pattern": "EXEC-001", "intent": "offensive"},
        ],
    })
    assert result["skill_classification"] == "malicious"
    assert result["findings"][0]["context"] == "execution"


def test_missing_api_key_raises():
    import os
    old = os.environ.pop("ANTHROPIC_API_KEY", None)
    try:
        a = SemanticAnalyzer(api_key=None)
        try:
            _ = a.client
            raise AssertionError("Should have raised")  # noqa: TRY301
        except RuntimeError as e:
            assert "ANTHROPIC_API_KEY" in str(e)
    finally:
        if old:
            os.environ["ANTHROPIC_API_KEY"] = old
