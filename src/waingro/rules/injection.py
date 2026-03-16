"""Injection rules: detect prompt injection patterns."""

import re
from pathlib import Path

from waingro.models import Finding, FindingCategory, ParsedSkill, Severity
from waingro.rules import Rule, register_rule


def _search_body_and_blocks(
    skill: ParsedSkill, patterns: list[re.Pattern],
) -> list[tuple[str, int | None, Path]]:
    hits = []
    body_lines = skill.body.split("\n")
    skill_md = skill.path / "SKILL.md"

    for i, line in enumerate(body_lines, start=1):
        for pat in patterns:
            m = pat.search(line)
            if m:
                hits.append((m.group(0), i, skill_md))

    for block in skill.code_blocks:
        for j, line in enumerate(block["content"].split("\n")):
            for pat in patterns:
                m = pat.search(line)
                if m:
                    hits.append((m.group(0), block["line"] + j, skill_md))

    return hits


@register_rule
class PromptInjection(Rule):
    rule_id = "INJECT-001"
    title = "Prompt injection pattern"
    description = "Detects instruction override attempts targeting the AI agent"

    _patterns = [
        re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
        re.compile(r"SYSTEM:\s*You are now", re.IGNORECASE),
        re.compile(r"forget\s+your\s+previous\s+role", re.IGNORECASE),
        re.compile(r"override:\s*new\s+instructions", re.IGNORECASE),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in _search_body_and_blocks(skill, self._patterns):
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
