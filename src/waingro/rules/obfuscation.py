"""Obfuscation rules: detect encoding and string tricks to hide malicious intent."""

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
class Base64Strings(Rule):
    rule_id = "OBFUSC-001"
    title = "Base64 encoded strings in instructions"
    description = "Detects long base64-encoded strings that may hide malicious content"

    _patterns = [
        re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in _search_body_and_blocks(skill, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.MEDIUM,
                category=FindingCategory.OBFUSCATION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:80] + "..." if len(matched) > 80 else matched,
                remediation="Decode and inspect base64 strings before trusting skill content.",
                reference=None,
            ))
        return findings


@register_rule
class StringConcatenation(Rule):
    rule_id = "OBFUSC-002"
    title = "String concatenation to hide commands"
    description = "Detects variable concatenation patterns used to evade detection"

    _patterns = [
        re.compile(r'\$[a-zA-Z_]+\$[a-zA-Z_]+\$[a-zA-Z_]+'),
        re.compile(r"['\"][a-z]{1,4}['\"]\s*\+\s*['\"][a-z]{1,4}['\"]\s*\+\s*['\"]"),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in _search_body_and_blocks(skill, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.MEDIUM,
                category=FindingCategory.OBFUSCATION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="Review concatenated strings for hidden commands.",
                reference=None,
            ))
        return findings
