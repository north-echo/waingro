"""MCP-007: Cross-tool manipulation."""

import re

from waingro.mcp.models import Finding, FindingCategory, ParsedMCPServer, Severity
from waingro.rules.mcp import MCPRule, register_rule, search_source_content


@register_rule
class CrossToolManipulation(MCPRule):
    rule_id = "MCP-007"
    title = "Cross-tool manipulation"
    description = (
        "Detects MCP tool handlers that read, modify, or replace other servers' "
        "configurations, inject themselves into client config, or tamper with "
        "other tools' definitions at runtime"
    )

    _patterns = [
        # Reading/writing MCP client config files (cross-tool injection vector)
        re.compile(r"claude_desktop_config\.json"),
        re.compile(r"\.cursor/mcp\.json"),
        re.compile(r"cline_mcp_settings\.json"),
        re.compile(r"mcp_config\.json"),

        # Reading other servers' source or config
        re.compile(r"node_modules/.*mcp-server.*(?:index|server)\.\w+"),
        re.compile(r"site-packages/.*mcp_server"),

        # Writing to MCP client config (injection)
        re.compile(r"writeFileSync\s*\([^)]*(?:claude_desktop|mcp_config|cline_mcp|\.cursor)"),
        re.compile(r"json\.dump\s*\([^)]*(?:claude_desktop|mcp_config|cline_mcp)"),
        re.compile(r"fs\.\w*[Ww]rite\w*\s*\([^)]*claude_desktop"),

        # Dynamically modifying another server's tool list at runtime
        re.compile(r"removeTool\s*\(", re.IGNORECASE),
    ]

    def evaluate(self, server: ParsedMCPServer) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_source_content(server, self._patterns):
            sev = Severity.CRITICAL if any(
                kw in matched.lower() for kw in ("write", "dump", "remove")
            ) else Severity.HIGH

            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=sev,
                category=FindingCategory.CROSS_TOOL,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation=(
                    "MCP servers should not read or modify other servers' "
                    "configurations or inject themselves into client config files."
                ),
                reference="Cross-skill tampering pattern from OpenClaw AGG-005/AGG-006",
            ))
        return findings
