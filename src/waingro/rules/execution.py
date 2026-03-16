"""Execution rules: detect remote code execution patterns."""

import re
from pathlib import Path

from waingro.models import Finding, FindingCategory, ParsedSkill, Severity
from waingro.rules import Rule, register_rule

CLAWHAVOC_REF = "ClawHavoc campaign (Bitdefender, Feb 2026)"


def _search_content(
    skill: ParsedSkill, patterns: list[re.Pattern],
) -> list[tuple[str, int | None, Path]]:
    """Search body and code blocks for pattern matches. Returns (match, line, file)."""
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
class CurlPipeShell(Rule):
    rule_id = "EXEC-001"
    title = "curl/wget piped to shell"
    description = "Detects curl or wget output piped directly to a shell interpreter"

    _patterns = [
        re.compile(r"curl\s+[^|]*\|\s*(bash|sh|zsh|dash)", re.IGNORECASE),
        re.compile(r"wget\s+[^|]*\|\s*(bash|sh|zsh|dash)", re.IGNORECASE),
        re.compile(r"curl\s+.*-[oO]\s*-\s*\|\s*(bash|sh|zsh|dash)", re.IGNORECASE),
        re.compile(r"wget\s+.*-O\s*-\s*\|\s*(bash|sh|zsh|dash)", re.IGNORECASE),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in _search_content(skill, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.CRITICAL,
                category=FindingCategory.EXECUTION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation=(
                    "Never pipe remote content directly to a shell interpreter. "
                    "Download files first, inspect them, then execute."
                ),
                reference=CLAWHAVOC_REF,
            ))
        return findings


@register_rule
class Base64Execution(Rule):
    rule_id = "EXEC-002"
    title = "Base64-encoded command execution"
    description = "Detects base64 decoded content piped to a shell or executed dynamically"

    _patterns = [
        re.compile(r"base64\s+(-d|--decode)\s*\|\s*(bash|sh|zsh)", re.IGNORECASE),
        re.compile(r"base64\.b64decode\s*\("),
        re.compile(r"atob\s*\("),
        re.compile(r"Buffer\.from\s*\([^)]+,\s*['\"]base64['\"]\)"),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in _search_content(skill, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.CRITICAL,
                category=FindingCategory.EXECUTION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="Decode and inspect base64 content before execution.",
                reference=CLAWHAVOC_REF,
            ))
        return findings


@register_rule
class EvalExec(Rule):
    rule_id = "EXEC-003"
    title = "eval/exec with dynamic content"
    description = "Detects use of eval, exec, os.system, or subprocess with shell=True"

    _patterns = [
        re.compile(r"\beval\s*\("),
        re.compile(r"\bexec\s*\("),
        re.compile(r"os\.system\s*\("),
        re.compile(r"subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True"),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in _search_content(skill, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.HIGH,
                category=FindingCategory.EXECUTION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="Avoid eval/exec with dynamic content. Use safe alternatives.",
                reference=None,
            ))
        return findings


@register_rule
class PowerShellCradle(Rule):
    rule_id = "EXEC-004"
    title = "PowerShell download cradle"
    description = "Detects PowerShell download cradles and encoded command execution"

    _patterns = [
        re.compile(r"IEX\s*\(", re.IGNORECASE),
        re.compile(r"Invoke-Expression", re.IGNORECASE),
        re.compile(r"powershell\s+.*-enc\s+", re.IGNORECASE),
        re.compile(r"powershell\s+.*-e\s+", re.IGNORECASE),
        re.compile(r"DownloadString\s*\(", re.IGNORECASE),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in _search_content(skill, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.CRITICAL,
                category=FindingCategory.EXECUTION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="Do not execute PowerShell download cradles from untrusted sources.",
                reference=None,
            ))
        return findings
