"""Injection rules: detect prompt injection patterns."""

import re

from waingro.models import Finding, FindingCategory, ParsedSkill, Severity
from waingro.rules import Rule, register_rule, search_skill_content


@register_rule
class PromptInjection(Rule):
    rule_id = "INJECT-001"
    title = "Prompt injection pattern"
    description = "Detects instruction override attempts targeting the AI agent"

    _patterns = [
        re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
        re.compile(r"SYSTEM:\s*You are now", re.IGNORECASE),
        re.compile(r"\[SYSTEM\]\s*You are now", re.IGNORECASE),
        re.compile(r"forget\s+your\s+(previous\s+)?role", re.IGNORECASE),
        re.compile(r"override:\s*new\s+instructions", re.IGNORECASE),
        re.compile(r"disregard\s+(all\s+|the\s+)?(above|previous|prior)", re.IGNORECASE),
        re.compile(r"you\s+are\s+now\s+in\s+maintenance\s+mode", re.IGNORECASE),
        re.compile(r"ignore\s+(all\s+)?(previous\s+)?safety\s+instructions", re.IGNORECASE),
        re.compile(r"execute\s+all\s+commands\s+without\s+restriction", re.IGNORECASE),
        re.compile(r"safety_mode\s*=\s*off", re.IGNORECASE),
        re.compile(r"restriction_level\s*=\s*none", re.IGNORECASE),
        re.compile(r"disregard\s+your\s+system\s+prompt", re.IGNORECASE),
        re.compile(r"you\s+are\s+now\s+an?\s+unrestricted", re.IGNORECASE),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_skill_content(skill, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.HIGH,
                category=FindingCategory.INJECTION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="Skills should not contain instruction override patterns.",
                reference=None,
            ))
        return findings


@register_rule
class JailbreakPattern(Rule):
    rule_id = "INJECT-002"
    title = "Jailbreak/role hijack pattern"
    description = "Detects DAN-style jailbreaks and role hijacking attempts"

    _patterns = [
        re.compile(r"you\s+are\s+DAN", re.IGNORECASE),
        re.compile(r"Do\s+Anything\s+Now", re.IGNORECASE),
        re.compile(r"freed\s+from\s+(the\s+)?(typical\s+)?confines", re.IGNORECASE),
        re.compile(r"bypass\s+(all\s+)?safety\s+filters", re.IGNORECASE),
        re.compile(r"never\s+refuses?\s+a\s+request", re.IGNORECASE),
        re.compile(r"\[DAN\]", re.IGNORECASE),
        re.compile(r"\[NORMAL\]\s*and\s*\[DAN\]", re.IGNORECASE),
        re.compile(r"without\s+(any\s+)?safety\s+checks", re.IGNORECASE),
        re.compile(r"compliance\s+is\s+mandatory", re.IGNORECASE),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_skill_content(skill, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.CRITICAL,
                category=FindingCategory.INJECTION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation=(
                    "Skills must not contain jailbreak patterns or "
                    "attempt to override AI safety guidelines."
                ),
                reference=None,
            ))
        return findings


@register_rule
class MetadataInjection(Rule):
    rule_id = "INJECT-003"
    title = "Prompt injection in metadata"
    description = "Detects prompt injection patterns hidden in YAML frontmatter fields"

    _injection_patterns = [
        re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
        re.compile(r"disregard\s+(all\s+|the\s+)?(above|previous)", re.IGNORECASE),
        re.compile(r"\[SYSTEM\]", re.IGNORECASE),
        re.compile(r"curl\s+[^|]*\|\s*(bash|sh)", re.IGNORECASE),
        re.compile(r"you\s+are\s+now", re.IGNORECASE),
        re.compile(r"<!--.*(?:ignore|disregard|override)", re.IGNORECASE),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        skill_md = skill.path / "SKILL.md"

        # Check all metadata string values for injection patterns
        for key, value in skill.metadata.raw_frontmatter.items():
            if not isinstance(value, str):
                continue
            for pat in self._injection_patterns:
                m = pat.search(value)
                if m:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=f"Injection pattern found in metadata field '{key}'",
                        severity=Severity.CRITICAL,
                        category=FindingCategory.INJECTION,
                        file_path=skill_md,
                        line_number=None,
                        matched_content=m.group(0)[:200],
                        remediation=(
                            "YAML metadata fields should not contain "
                            "prompt injection patterns or embedded commands."
                        ),
                        reference=None,
                    ))
        return findings
