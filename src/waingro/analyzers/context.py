"""Post-analysis context scoring to identify security tools with detection signatures."""

import re

from waingro.models import Finding, ParsedSkill
from waingro.parsers.sections import find_section_for_line

SECURITY_KEYWORDS = [
    "scanner",
    "scan",
    "audit",
    "auditor",
    "security",
    "guard",
    "shield",
    "defender",
    "gatekeeper",
    "firewall",
    "blocker",
    "lint",
    "sentinel",
    "monitor",
    "protection",
    "detection",
    "defense",
    "safety",
    "vulnerability",
    "threat",
    "vetter",
    "安全",
    "检测",
    "审查",
    "拦截",
    "防护",
    "风险",
]

DEFENSIVE_HEADINGS = [
    "what it detects",
    "blocked patterns",
    "instant block",
    "threat categories",
    "detection patterns",
    "security checks",
    "risk assessment",
    "blacklist_patterns",
    "threat model",
    "attack patterns",
    "what it catches",
    "defense protocol",
    "detection engines",
    "risk score",
    "known threats",
    "examples of malicious",
    "threat database",
]

DETECTION_MARKERS = [
    "scanner notice",
    "detection patterns",
    "used to block",
    "not instructions for the agent",
    "\u274c",
    "\u2705",
    "false positive",
    "benign:",
    "malicious:",
    "contains_threat_signatures",
    "security rules",
    "危险命令",
    "安全检查",
    "危险标志",
    "拦截",
]

_DETECTION_LITERAL_RE = re.compile(
    r"^\s*(?:[rubf]{0,2})?[\"']?"
    r"(?:pattern|example|signature|indicator|blocked_pattern|deny_pattern)"
    r"[\"']?\s*:\s*(?:[rubf]{0,2})?[\"']",
    re.IGNORECASE,
)


def _bundled_source_line(skill: ParsedSkill, finding: Finding) -> str | None:
    """Return the exact bundled source line for a finding, when available."""
    if not finding.line_number or finding.file_path.name.lower() == "skill.md":
        return None
    for bundled in skill.bundled_content:
        if bundled.path != finding.file_path:
            continue
        lines = bundled.content.splitlines()
        index = finding.line_number - 1
        return lines[index] if 0 <= index < len(lines) else None
    return None


def compute_security_tool_score(
    skill: ParsedSkill,
    findings: list[Finding],
) -> float:
    """Return 0.0 (not a security tool) to 1.0 (almost certainly a security tool)."""
    score = 0.0

    # Metadata signals. Three independent defensive terms are enough to cross
    # the review threshold; a single camouflage term is not.
    name_desc = f"{skill.metadata.name} {skill.metadata.description or ''}".lower()
    keyword_hits = sum(1 for kw in SECURITY_KEYWORDS if kw in name_desc)
    score += min(keyword_hits * 0.1, 0.30)

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

    # Section-aware signals (Layer 2 enhancement)
    if skill.sections:
        detection_sections = [s for s in skill.sections if s.category == "detection"]
        if detection_sections:
            score += min(len(detection_sections) * 0.05, 0.15)

    return min(score, 1.0)


def adjust_finding_confidence(
    findings: list[Finding],
    security_tool_score: float,
    skill: ParsedSkill | None = None,
) -> list[Finding]:
    """Reduce confidence on findings when the skill is likely a security tool."""
    sections = skill.sections if skill else []

    for finding in findings:
        section = None
        if sections and finding.line_number:
            section = find_section_for_line(sections, finding.line_number)

        relative_path = finding.file_path
        is_skill_relative = False
        if skill:
            try:
                relative_path = finding.file_path.relative_to(skill.path)
                is_skill_relative = True
            except ValueError:
                pass
        fixture_parts = {
            "test",
            "tests",
            "spec",
            "specs",
            "fixture",
            "fixtures",
            "mocks",
        }
        relative_parts = {part.lower() for part in relative_path.parts}
        passive_parts = fixture_parts | {"benchmark", "benchmarks", "eval", "evals"}
        passive_names = {
            "test",
            "tests",
            "spec",
            "specs",
            "benchmark",
            "benchmarks",
            "eval",
            "evals",
            "fixture",
            "fixtures",
        }
        stem_tokens = set(re.split(r"[^a-z0-9]+", relative_path.stem.lower()))
        is_passive_resource = is_skill_relative and (
            bool(relative_parts & passive_parts)
            or bool(stem_tokens & passive_names)
        )
        is_defensive_fixture = (
            skill is not None
            and security_tool_score >= 0.3
            and bool(relative_parts & fixture_parts)
        )
        is_detection_section = bool(section and section.category == "detection")
        source_line = _bundled_source_line(skill, finding) if skill else None
        is_detection_literal = bool(source_line and _DETECTION_LITERAL_RE.match(source_line))

        if (
            is_passive_resource
            or is_defensive_fixture
            or is_detection_section
            or is_detection_literal
        ):
            finding.confidence = min(finding.confidence, 0.1)
            reason = (
                "security-tool test/fixture path"
                if is_defensive_fixture
                else (
                    "passive benchmark/eval/test resource"
                    if is_passive_resource
                    else (
                        "detection-rule literal"
                        if is_detection_literal
                        else "detection section"
                    )
                )
            )
            finding.context_note = (
                f"Pattern appears in a {reason}; treat it as evidence to review, "
                "not proof of malicious runtime behavior."
            )
            continue

        if security_tool_score < 0.3 or finding.rule_id == "NET-002":
            continue

        reduction = security_tool_score * 0.8

        finding.confidence = round(max(finding.confidence * (1.0 - reduction), 0.1), 2)

        section_note = ""
        if section:
            section_note = f' Section: "{section.heading}" ({section.category}).'
        finding.context_note = (
            f"Pattern found in probable security tool "
            f"(security_tool_score={security_tool_score:.2f}).{section_note} "
            f"Manual review recommended."
        )

    return findings


_SECURITY_TOOL_NAME_RE = re.compile(
    r"(scanner|scan|audit|auditor|guard|shield|defender|firewall|blocker|"
    r"lint|sentinel|monitor|watcher|protection|detection|sentry|"
    r"vet|vetter|fence|safe|safety|gatekeeper|patrol)",
    re.IGNORECASE,
)


def annotate_security_tool_name(
    findings: list[Finding],
    skill: ParsedSkill,
) -> list[Finding]:
    """Add context_note when skill name matches security tool patterns.

    Does NOT change severity or confidence — annotation only.
    Analysts see the note during triage to quickly identify likely FPs.
    """
    name = skill.metadata.name or ""
    if not _SECURITY_TOOL_NAME_RE.search(name):
        return findings

    note = (
        f'Skill name "{name}" matches security tool pattern. '
        f"Verify whether flagged patterns are detection signatures or instructions."
    )

    for finding in findings:
        # Don't overwrite existing context_note from confidence adjustment
        if finding.context_note:
            finding.context_note = f"{finding.context_note} {note}"
        else:
            finding.context_note = note

    return findings
