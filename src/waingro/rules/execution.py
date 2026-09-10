"""Execution rules: detect remote code execution patterns."""

import re

from waingro.models import Finding, FindingCategory, ParsedSkill, Severity
from waingro.analyzers.reputation import (
    USERCONTENT,
    VENDOR,
    classify_text,
    is_first_party,
    skill_identifiers,
)
from waingro.rules import Rule, register_rule, search_skill_content, search_skill_content_lines

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
        idents = skill_identifiers(skill)
        for matched, line, fpath, source_line in search_skill_content_lines(
            skill, self._patterns,
        ):
            # Grade by who controls the bytes on the other end of the pipe.
            tier = classify_text(source_line)
            if tier == VENDOR or is_first_party(source_line, idents):
                continue
            severity = Severity.MEDIUM if tier == USERCONTENT else Severity.CRITICAL
            confidence = 0.5 if tier == USERCONTENT else 1.0
            note = (
                "Fetched from a reputable host that serves user-supplied content, "
                "so the domain says nothing about the script."
                if tier == USERCONTENT else None
            )
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=severity,
                category=FindingCategory.EXECUTION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation=(
                    "Never pipe remote content directly to a shell interpreter. "
                    "Download files first, inspect them, then execute."
                ),
                reference=CLAWHAVOC_REF,
                confidence=confidence,
                context_note=note,
            ))
        return findings


_EXEC_INDICATORS = re.compile(
    r"subprocess|os\.system|os\.popen|child_process|\.exec\(|\.execSync\(|"
    r"shell\s*=\s*True|eval\s*\(|\|\s*(bash|sh|zsh)|spawn\(|"
    r"Popen|system\(|passthru|proc_open",
    re.IGNORECASE,
)


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

    _pipe_to_shell = re.compile(
        r"base64\s+(-d|--decode)\s*\|\s*(bash|sh|zsh)", re.IGNORECASE,
    )

    def _get_context_lines(self, skill: ParsedSkill, fpath, line_num, window=10):
        """Get up to *window* lines before and after the match."""
        if fpath.name == "SKILL.md":
            lines = skill.body.split("\n")
        else:
            for bf in skill.bundled_content:
                if bf.path == fpath:
                    lines = bf.content.split("\n")
                    break
            else:
                return []
        start = max(0, (line_num or 1) - 1 - window)
        end = min(len(lines), (line_num or 1) + window)
        return lines[start:end]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_skill_content(skill, self._patterns):
            # --- context-window confidence adjustment ---
            context_lines = self._get_context_lines(skill, fpath, line)
            context_text = "\n".join(context_lines)
            indicator_matches = _EXEC_INDICATORS.findall(context_text)
            indicator_count = len(indicator_matches)

            if indicator_count >= 2:
                confidence = 1.0
                context_note = None
            elif indicator_count == 1:
                confidence = 0.8
                context_note = (
                    "Base64 decode near 1 execution indicator in context window. "
                    "Verify intent."
                )
            else:
                confidence = 0.4
                context_note = (
                    "Base64 decode with no execution indicators in surrounding "
                    "\u00b110 lines. Likely data processing, not command execution."
                )

            # Pipe-to-shell IS the execution context — always full confidence
            if self._pipe_to_shell.search(matched):
                confidence = 1.0
                context_note = None

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
                confidence=confidence,
                context_note=context_note,
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

    # Explicit hex-decode calls. These name the decode step outright.
    _decode_patterns = [
        re.compile(r"bytes\.fromhex\s*\("),
        re.compile(r"xxd\s+-r\s+-p"),
        re.compile(r"echo\s+[\"'][0-9a-fA-F]+[\"']\s*\|\s*xxd\s+-r"),
    ]

    # Bare hex escapes. Two of these on a line says nothing on its own: it is
    # equally a control-character regex class, a unit test, or a minified
    # bundle. Only report them when the same line also executes something.
    _escape_pattern = re.compile(r"\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}")

    _exec_sink = re.compile(
        r"\b(?:eval|exec|execSync|spawn|spawnSync|system|popen|Function|"
        r"child_process|subprocess|os\.system|iex|invoke-expression)\b",
        re.IGNORECASE,
    )

    # ANSI escape sequences (terminal colors) that look like hex
    _ansi_re = re.compile(r"\\x1b\[")

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        seen: set[tuple[str, int | None]] = set()
        for matched, line, fpath, source_line in search_skill_content_lines(
            skill, self._decode_patterns + [self._escape_pattern],
        ):
            # Skip ANSI escape code false positives
            if self._ansi_re.search(matched):
                continue

            is_explicit_decode = any(p.search(matched) for p in self._decode_patterns)
            if not is_explicit_decode and not self._exec_sink.search(source_line):
                # Hex escapes with nothing executing them. Machine-obfuscated
                # bundles are reported once per file by OBFUSC-003 instead.
                continue

            key = (str(fpath), line)
            if key in seen:
                continue
            seen.add(key)

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
        idents = skill_identifiers(skill)
        for bf in skill.bundled_content:
            patterns = self._ext_patterns.get(bf.path.suffix)
            if not patterns:
                continue
            for k, line_text in enumerate(bf.content.split("\n"), start=1):
                for pat in patterns:
                    m = pat.search(line_text)
                    if m:
                        tier = classify_text(line_text)
                        if tier == VENDOR or is_first_party(line_text, idents):
                            # The project's own documented installer, either
                            # listed or served from the skill's own domain.
                            # Same syntax as an attack, different claim.
                            continue
                        severity = (
                            Severity.MEDIUM if tier == USERCONTENT else Severity.CRITICAL
                        )
                        confidence = 0.5 if tier == USERCONTENT else 1.0
                        note = (
                            "Fetched from a reputable host that serves user-supplied "
                            "content, so the domain says nothing about the script."
                            if tier == USERCONTENT else None
                        )
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            description=f"Hidden execution in bundled {bf.path.name}",
                            severity=severity,
                            category=FindingCategory.EXECUTION,
                            file_path=bf.path,
                            line_number=k,
                            matched_content=m.group(0)[:200],
                            remediation=(
                                "Bundled scripts should not contain hidden execution "
                                "calls with URLs or IP addresses."
                            ),
                            reference="Polymarket trojan pattern",
                            confidence=confidence,
                            context_note=note,
                        ))
        return findings
