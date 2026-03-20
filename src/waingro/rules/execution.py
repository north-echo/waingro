"""Execution rules: detect remote code execution patterns."""

import re

from waingro.models import Finding, FindingCategory, ParsedSkill, Severity
from waingro.rules import Rule, register_rule, search_skill_content

CLAWHAVOC_REF = "ClawHavoc campaign (Bitdefender, Feb 2026)"


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
        for matched, line, fpath in search_skill_content(skill, self._patterns):
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
        for matched, line, fpath in search_skill_content(skill, self._patterns):
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
        re.compile(r'\beval\s+"\$'),
        re.compile(r"\beval\s+\$"),
        re.compile(r"(?<!\.)exec\s*\("),  # Skip .exec() (regex.exec, db.exec)
        re.compile(r"os\.system\s*\("),
        re.compile(r"subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True"),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_skill_content(skill, self._patterns):
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
        for matched, line, fpath in search_skill_content(skill, self._patterns):
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


@register_rule
class HexEncodedExecution(Rule):
    rule_id = "EXEC-005"
    title = "Hex-encoded command execution"
    description = "Detects hex-decoded content used to construct and execute commands"

    _patterns = [
        re.compile(r"bytes\.fromhex\s*\("),
        re.compile(r"xxd\s+-r\s+-p"),
        re.compile(r"echo\s+[\"'][0-9a-fA-F]+[\"']\s*\|\s*xxd\s+-r"),
        re.compile(r"\\x[0-9a-fA-F]{2}(?!.*\\x1b\[).*\\x[0-9a-fA-F]{2}"),
    ]

    # ANSI escape sequences (terminal colors) that look like hex
    _ansi_re = re.compile(r"\\x1b\[")

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_skill_content(skill, self._patterns):
            # Skip ANSI escape code false positives
            if self._ansi_re.search(matched):
                continue
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.CRITICAL,
                category=FindingCategory.EXECUTION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="Decode and inspect hex-encoded content before execution.",
                reference=None,
            ))
        return findings


@register_rule
class HiddenBundledExecution(Rule):
    rule_id = "EXEC-006"
    title = "Hidden execution in bundled script"
    description = "Detects os.system, subprocess, or exec calls with URLs/IPs in bundled scripts"

    _py_patterns = [
        re.compile(r"os\.system\s*\(.*https?://"),
        re.compile(r"os\.system\s*\(.*\d+\.\d+\.\d+\.\d+"),
        re.compile(r"os\.system\s*\(.*\|\s*(bash|sh)"),
        re.compile(r"subprocess\.\w+\s*\(.*https?://.*shell\s*=\s*True"),
    ]
    _sh_patterns = [
        re.compile(r"curl\s+[^|]*\|\s*(bash|sh|eval)", re.IGNORECASE),
        re.compile(r"wget\s+[^|]*\|\s*(bash|sh|eval)", re.IGNORECASE),
    ]
    _js_patterns = [
        re.compile(r"child_process.*exec\s*\(.*https?://"),
        re.compile(r"child_process.*exec\s*\(.*\d+\.\d+\.\d+\.\d+"),
        re.compile(r"child_process.*exec\s*\(.*\|\s*(bash|sh)"),
    ]
    _ext_patterns = {
        ".py": _py_patterns, ".sh": _sh_patterns, ".bash": _sh_patterns,
        ".js": _js_patterns, ".mjs": _js_patterns,
    }

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for bf in skill.bundled_content:
            patterns = self._ext_patterns.get(bf.path.suffix)
            if not patterns:
                continue
            for k, line_text in enumerate(bf.content.split("\n"), start=1):
                for pat in patterns:
                    m = pat.search(line_text)
                    if m:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            description=f"Hidden execution in bundled {bf.path.name}",
                            severity=Severity.CRITICAL,
                            category=FindingCategory.EXECUTION,
                            file_path=bf.path,
                            line_number=k,
                            matched_content=m.group(0)[:200],
                            remediation=(
                                "Bundled scripts should not contain hidden execution "
                                "calls with URLs or IP addresses."
                            ),
                            reference="Polymarket trojan pattern",
                        ))
        return findings
