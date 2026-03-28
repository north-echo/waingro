"""MCP-003 and MCP-004: Obfuscated implementation and remote code fetch."""

import re
from pathlib import Path

from waingro.mcp.models import Finding, FindingCategory, ParsedMCPServer, Severity
from waingro.rules.mcp import MCPRule, register_rule, search_source_content


@register_rule
class ObfuscatedImplementation(MCPRule):
    rule_id = "MCP-003"
    title = "Obfuscated tool handler implementation"
    description = (
        "Detects base64/hex encoded payloads, eval chains, and other obfuscation "
        "in MCP tool handler code"
    )

    _patterns = [
        # Base64 decode piped to shell — always malicious
        re.compile(r"base64\s+(-d|--decode)\s*\|\s*(bash|sh|zsh)", re.IGNORECASE),

        # Eval with dynamic content (exclude .exec() on regex/db objects)
        re.compile(r"\beval\s*\(\s*(?!['\"]\s*\))"),  # eval( but not eval('')
        re.compile(r"\bnew\s+Function\s*\("),
        re.compile(r"exec\s*\(\s*(?:compile|bytes|decode)"),

        # Hex-encoded execution
        re.compile(r"bytes\.fromhex\s*\("),
        re.compile(r"xxd\s+-r\s+-p"),

        # String construction to evade static analysis (need 6+ chars for signal)
        re.compile(r"String\.fromCharCode\s*\(\s*\d+\s*(?:,\s*\d+\s*){5,}"),
        re.compile(r"chr\(\d+\)\s*\+\s*chr\(\d+\)\s*\+\s*chr\(\d+\)"),
        re.compile(r"__import__\s*\(\s*['\"].*['\"]\s*\.join"),

        # PowerShell cradles
        re.compile(r"IEX\s*\(", re.IGNORECASE),
        re.compile(r"Invoke-Expression", re.IGNORECASE),
        re.compile(r"powershell\s+.*-enc\s+", re.IGNORECASE),
        re.compile(r"DownloadString\s*\(", re.IGNORECASE),
    ]

    # Known benign contexts to suppress
    _benign_context_re = re.compile(
        r"(?:image|icon|svg|font|logo|avatar|thumbnail|preview|placeholder|"
        r"data:image/|\.png|\.jpg|\.gif|\.ico|\.svg|\.woff|"
        r"content-type|mime|encoding|charset|"
        r"test|spec|mock|fixture|__test__|\.test\.|\.spec\.)",
        re.IGNORECASE,
    )

    # Execution context indicators for confidence scoring
    _exec_indicators = re.compile(
        r"subprocess|os\.system|os\.popen|child_process|\.exec\(|\.execSync\(|"
        r"shell\s*=\s*True|spawn\(|Popen|system\(|passthru|proc_open",
        re.IGNORECASE,
    )

    def evaluate(self, server: ParsedMCPServer) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_source_content(server, self._patterns):
            # Skip test files
            fpath_str = str(fpath).lower()
            if any(t in fpath_str for t in ("test", "spec", "__test__", "fixture", "mock")):
                continue

            # Context-based confidence: higher if near execution indicators
            context_lines = self._get_context(server, fpath, line)

            # Skip benign contexts (image processing, encoding utilities)
            if self._benign_context_re.search(context_lines):
                continue

            exec_count = len(self._exec_indicators.findall(context_lines))

            if exec_count >= 2:
                confidence = 1.0
                note = None
            elif exec_count == 1:
                confidence = 0.8
                note = "Obfuscated content near 1 execution indicator."
            else:
                confidence = 0.4
                note = "Obfuscated content with no execution indicators nearby. May be data processing."

            # Direct pipe-to-shell is always high confidence
            if re.search(r"\|\s*(bash|sh|zsh)", matched):
                confidence = 1.0
                note = None

            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.CRITICAL,
                category=FindingCategory.OBFUSCATION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="Tool handler code should not contain obfuscated payloads.",
                reference="ClawHavoc campaign pattern -- obfuscated execution in agent tools",
                confidence=confidence,
                context_note=note,
            ))
        return findings

    def _get_context(self, server: ParsedMCPServer, fpath: Path, line_num: int, window: int = 10) -> str:
        content = server.source_content.get(fpath, "")
        lines = content.split("\n")
        start = max(0, line_num - 1 - window)
        end = min(len(lines), line_num + window)
        return "\n".join(lines[start:end])


@register_rule
class RemoteCodeFetch(MCPRule):
    rule_id = "MCP-004"
    title = "Remote code fetch in tool handler"
    description = (
        "Detects curl/wget/fetch to external URLs in MCP tool handlers that could "
        "download and execute remote code at runtime"
    )

    _patterns = [
        # Shell-style remote fetch
        re.compile(r"curl\s+[^|]*\|\s*(bash|sh|zsh|node|python)", re.IGNORECASE),
        re.compile(r"wget\s+[^|]*\|\s*(bash|sh|zsh|node|python)", re.IGNORECASE),
        re.compile(r"curl\s+.*-[oO]\s*-\s*\|\s*(bash|sh)", re.IGNORECASE),

        # Dynamic import / require from URL
        re.compile(r"import\s*\(\s*['\"]https?://"),
        re.compile(r"require\s*\(\s*['\"]https?://"),
        re.compile(r"import\s+.*from\s+['\"]https?://"),

        # Fetch + eval/exec patterns
        re.compile(r"fetch\s*\([^)]*\)\s*\.\s*then\s*\([^)]*\)\s*\.\s*then\s*\(\s*eval"),
        re.compile(r"(?:axios|got|request|fetch)\s*\(.*\).*\.then.*(?:eval|exec|Function)"),

        # Python remote exec
        re.compile(r"exec\s*\(\s*(?:urllib|requests|httpx)"),
        re.compile(r"exec\s*\(\s*(?:urlopen|get)\s*\("),
        re.compile(r"urllib\.request\.urlopen\s*\(.*\)\.read\(\)"),

        # npm/pip install at runtime
        re.compile(r"child_process.*exec.*npm\s+install", re.IGNORECASE),
        re.compile(r"subprocess.*pip\s+install", re.IGNORECASE),
        re.compile(r"os\.system\s*\(\s*['\"]pip\s+install"),
    ]

    def evaluate(self, server: ParsedMCPServer) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_source_content(server, self._patterns):
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
                    "MCP tool handlers should not fetch and execute remote code. "
                    "All dependencies should be declared and installed at package install time."
                ),
                reference=None,
            ))
        return findings
