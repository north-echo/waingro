"""Multi-dimensional risk scoring for scan results."""

from __future__ import annotations

from dataclasses import dataclass

from waingro.models import Finding, FindingCategory, Severity

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.7,
    Severity.MEDIUM: 0.3,
    Severity.LOW: 0.1,
    Severity.INFO: 0.0,
}

CATEGORY_DIMENSION = {
    FindingCategory.EXECUTION: "execution_risk",
    FindingCategory.EXFILTRATION: "exfiltration_risk",
    FindingCategory.PERSISTENCE: "persistence_risk",
    FindingCategory.NETWORK: "network_risk",
    FindingCategory.INJECTION: "injection_risk",
    FindingCategory.OBFUSCATION: "execution_risk",
    FindingCategory.SOCIAL_ENGINEERING: "execution_risk",
    FindingCategory.TYPOSQUATTING: "execution_risk",
}


@dataclass
class RiskProfile:
    execution_risk: float = 0.0
    exfiltration_risk: float = 0.0
    persistence_risk: float = 0.0
    network_risk: float = 0.0
    injection_risk: float = 0.0
    overall_risk: float = 0.0
    security_tool_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "execution_risk": round(self.execution_risk, 3),
            "exfiltration_risk": round(self.exfiltration_risk, 3),
            "persistence_risk": round(self.persistence_risk, 3),
            "network_risk": round(self.network_risk, 3),
            "injection_risk": round(self.injection_risk, 3),
            "overall_risk": round(self.overall_risk, 3),
            "security_tool_score": round(self.security_tool_score, 3),
        }


def is_scanner_profile(findings: list[Finding]) -> bool:
    """Detect the scanner profile: many diverse patterns with no real C2."""
    categories = {f.category for f in findings}
    has_c2 = any(f.rule_id == "NET-002" for f in findings)
    return len(categories) >= 4 and len(findings) >= 8 and not has_c2


def compute_risk_profile(
    findings: list[Finding], security_tool_score: float,
) -> RiskProfile:
    """Compute dimensional risk scores from findings and security tool context."""
    dims: dict[str, float] = {
        "execution_risk": 0.0,
        "exfiltration_risk": 0.0,
        "persistence_risk": 0.0,
        "network_risk": 0.0,
        "injection_risk": 0.0,
    }

    for finding in findings:
        dim = CATEGORY_DIMENSION.get(finding.category, "execution_risk")
        sev_weight = SEVERITY_WEIGHT.get(finding.severity, 0.0)
        contribution = sev_weight * finding.confidence * 0.2
        dims[dim] = min(dims[dim] + contribution, 1.0)

    # Network risk gets 2x weight in overall calculation
    weights = {
        "execution_risk": 1.0,
        "exfiltration_risk": 1.0,
        "persistence_risk": 0.8,
        "network_risk": 2.0,
        "injection_risk": 1.0,
    }
    total_weight = sum(weights.values())
    overall = sum(dims[d] * weights[d] for d in dims) / total_weight

    # Security tool score dampens overall risk
    if security_tool_score >= 0.3:
        dampener = 1.0 - (security_tool_score * 0.6)
        overall *= dampener

    profile = RiskProfile(
        execution_risk=round(dims["execution_risk"], 3),
        exfiltration_risk=round(dims["exfiltration_risk"], 3),
        persistence_risk=round(dims["persistence_risk"], 3),
        network_risk=round(dims["network_risk"], 3),
        injection_risk=round(dims["injection_risk"], 3),
        overall_risk=round(min(overall, 1.0), 3),
        security_tool_score=round(security_tool_score, 3),
    )
    return profile


def verdict_from_profile(profile: RiskProfile) -> str:
    """Compute verdict from risk profile."""
    if profile.network_risk >= 0.8 and profile.security_tool_score < 0.3:
        return "MALICIOUS"
    if profile.overall_risk >= 0.7 and profile.security_tool_score < 0.3:
        return "MALICIOUS"
    if profile.overall_risk >= 0.5 and profile.security_tool_score < 0.5:
        return "SUSPICIOUS"
    if profile.security_tool_score >= 0.5:
        return "REVIEW"
    if profile.overall_risk >= 0.3:
        return "WARNING"
    return "CLEAN"
