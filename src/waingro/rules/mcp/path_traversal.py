"""MCP-012: Path traversal in tool handlers."""

import re

from waingro.mcp.models import Finding, FindingCategory, ParsedMCPServer, Severity
from waingro.rules.mcp import MCPRule, register_rule, search_source_content


@register_rule
class PathTraversal(MCPRule):
    rule_id = "MCP-012"
    title = "Path traversal vulnerability"
    description = (
        "Detects MCP tool handlers that construct file paths from user input "
        "without sanitization. 82% of surveyed MCP implementations using file "
        "operations are vulnerable to path traversal. Adversa #10."
    )

    # Patterns indicating unsanitized path construction
    _vulnerable_patterns = [
        # Direct string concatenation for paths
        re.compile(r"path\.join\s*\(\s*\w+\s*,\s*(?:req|args|params|input|arguments)\b"),
        re.compile(r"path\.resolve\s*\(\s*\w+\s*,\s*(?:req|args|params|input|arguments)\b"),
        re.compile(r"os\.path\.join\s*\(\s*\w+\s*,\s*(?:req|args|params|input|arguments)\b"),

        # readdir/stat with user-controlled paths
        re.compile(r"(?:readdir|stat|lstat|access|mkdir)\s*\(\s*(?:args|params|input|arguments)"),

        # readFile/writeFile with user-controlled paths (no validation)
        re.compile(r"(?:readFile|writeFile|readFileSync|writeFileSync|unlink)\s*\(\s*(?:args|params|input|arguments)"),
        re.compile(r"open\s*\(\s*(?:args|params|input|arguments)"),
    ]

    # Patterns indicating path sanitization IS present (reduces confidence)
    _sanitization_re = re.compile(
        r"(?:realpath|normalize|resolve|isAbsolute|startsWith|includes\(\s*['\"]\.\.)|"
        r"path\.relative|sanitize|validate.*path|allowedPaths|pathTraversal|"
        r"openFileWithinRoot|isPathInside|safePath",
        re.IGNORECASE,
    )

    def evaluate(self, server: ParsedMCPServer) -> list[Finding]:
        findings = []
        all_source = server.all_source_text
        has_sanitization = bool(self._sanitization_re.search(all_source))

        for matched, line, fpath in search_source_content(server, self._vulnerable_patterns):
            # Check nearby context for sanitization
            context = self._get_context(server, fpath, line)
            local_sanitization = bool(self._sanitization_re.search(context))

            if local_sanitization:
                continue  # Sanitization found near the pattern

            confidence = 0.5 if has_sanitization else 0.8

            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.HIGH,
                category=FindingCategory.EXECUTION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation=(
                    "Validate and sanitize all file paths from user input. "
                    "Use realpath() + startsWith() to enforce directory boundaries. "
                    "Reject paths containing '..' components."
                ),
                reference="Adversa #10; 82% of file-handling MCP servers vulnerable; CVE-2025-66689",
                confidence=confidence,
            ))

        return findings

    def _get_context(self, server, fpath, line_num, window=15):
        content = server.source_content.get(fpath, "")
        lines = content.split("\n")
        start = max(0, line_num - 1 - window)
        end = min(len(lines), line_num + window)
        return "\n".join(lines[start:end])
