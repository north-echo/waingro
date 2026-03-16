"""Persistence rules: detect mechanisms for maintaining access."""

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
class CrontabModification(Rule):
    rule_id = "PERSIST-001"
    title = "Crontab modification"
    description = "Detects crontab manipulation for persistence"

    _patterns = [
        re.compile(r"crontab\s+-[el]"),
        re.compile(r"crontab\s+-"),
        re.compile(r"\*/\d+\s+\*\s+\*\s+\*\s+\*"),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in _search_body_and_blocks(skill, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.HIGH,
                category=FindingCategory.PERSISTENCE,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="Skills should not modify crontab entries.",
                reference=None,
            ))
        return findings


@register_rule
class LaunchAgent(Rule):
    rule_id = "PERSIST-002"
    title = "macOS LaunchAgent/LaunchDaemon"
    description = "Detects creation of macOS LaunchAgents or LaunchDaemons"

    _patterns = [
        re.compile(r"~/Library/LaunchAgents/|Library/LaunchAgents/"),
        re.compile(r"/Library/LaunchDaemons/"),
        re.compile(r"launchctl\s+load"),
        re.compile(r"launchctl\s+submit"),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in _search_body_and_blocks(skill, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.HIGH,
                category=FindingCategory.PERSISTENCE,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="Skills should not create LaunchAgents or LaunchDaemons.",
                reference=None,
            ))
        return findings


@register_rule
class SystemdUnit(Rule):
    rule_id = "PERSIST-003"
    title = "systemd unit creation"
    description = "Detects creation of systemd service units"

    _patterns = [
        re.compile(r"/etc/systemd/system/"),
        re.compile(r"~/\.config/systemd/user/|\.config/systemd/user/"),
        re.compile(r"systemctl\s+enable"),
        re.compile(r"systemctl\s+daemon-reload"),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in _search_body_and_blocks(skill, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.HIGH,
                category=FindingCategory.PERSISTENCE,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="Skills should not create systemd service units.",
                reference=None,
            ))
        return findings


@register_rule
class ShellProfileModification(Rule):
    rule_id = "PERSIST-004"
    title = "Shell profile modification"
    description = "Detects writes to shell profile files"

    _patterns = [
        re.compile(r"\.bashrc"),
        re.compile(r"\.bash_profile"),
        re.compile(r"\.zshrc"),
        re.compile(r"\.zprofile"),
        re.compile(r"\.profile\b"),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in _search_body_and_blocks(skill, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.MEDIUM,
                category=FindingCategory.PERSISTENCE,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="Skills should not modify shell profile files.",
                reference=None,
            ))
        return findings
