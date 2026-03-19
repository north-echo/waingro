"""Post-analysis context scoring to identify security tools with detection signatures."""

from waingro.models import Finding, ParsedSkill

SECURITY_KEYWORDS = [
    "scanner", "scan", "audit", "auditor", "security", "guard",
    "shield", "defender", "firewall", "blocker", "lint", "sentinel",
    "monitor", "protection", "detection", "defense", "safety",
]

DEFENSIVE_HEADINGS = [
    "what it detects", "blocked patterns", "instant block",
    "threat categories", "detection patterns", "security checks",
    "risk assessment", "blacklist_patterns", "threat model",
    "attack patterns", "what it catches", "defense protocol",
    "detection engines", "risk score", "known threats",
    "examples of malicious", "threat database",
]

DETECTION_MARKERS = [
    "scanner notice", "detection patterns", "used to block",
    "not instructions for the agent", "\u274c", "\u2705",
    "false positive", "benign:", "malicious:",
    "contains_threat_signatures",
]


def compute_security_tool_score(
    skill: ParsedSkill, findings: list[Finding],
) -> float:
    """Return 0.0 (not a security tool) to 1.0 (almost certainly a security tool)."""
    score = 0.0

    # Metadata signals (max +0.35)
    name_desc = f"{skill.metadata.name} {skill.metadata.description or ''}".lower()
    keyword_hits = sum(1 for kw in SECURITY_KEYWORDS if kw in name_desc)
    score += min(keyword_hits * 0.1, 0.25)

    raw_fm = skill.metadata.raw_frontmatter
    if raw_fm.get("security_tool") or raw_fm.get("contains_threat_signatures"):
        score += 0.1
    metadata_block = str(raw_fm.get("metadata", "")).lower()
    if "security" in metadata_block or "category" in metadata_block:
        score += 0.05
    tags = [t.lower() for t in skill.metadata.tags]
    if any(t in tags for t in ["security", "audit", "scanner", "detection"]):
        score += 0.05

    # Structural signals (max +0.35)
    body_lower = skill.body.lower()
    heading_hits = sum(1 for h in DEFENSIVE_HEADINGS if h in body_lower)
    score += min(heading_hits * 0.07, 0.25)

    marker_hits = sum(1 for m in DETECTION_MARKERS if m in body_lower)
    score += min(marker_hits * 0.05, 0.10)

    # Multi-rule signals (max +0.30)
    categories_hit = {f.category for f in findings}
    if len(categories_hit) >= 4:
        score += 0.15
    if len(categories_hit) >= 6:
        score += 0.10
    has_c2 = any(f.rule_id == "NET-002" for f in findings)
    if not has_c2 and len(findings) >= 5:
        score += 0.05

    return min(score, 1.0)


def adjust_finding_confidence(
    findings: list[Finding], security_tool_score: float,
) -> list[Finding]:
    """Reduce confidence on findings when the skill is likely a security tool."""
    if security_tool_score < 0.3:
        return findings

    for finding in findings:
        # Never reduce confidence on NET-002 (known C2 IPs)
        if finding.rule_id == "NET-002":
            continue

        reduction = security_tool_score * 0.8
        finding.confidence = round(max(1.0 - reduction, 0.1), 2)
        finding.context_note = (
            f"Pattern found in probable security tool "
            f"(security_tool_score={security_tool_score:.2f}). "
            f"Manual review recommended."
        )

    return findings
