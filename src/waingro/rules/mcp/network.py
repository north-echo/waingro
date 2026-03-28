"""MCP-008: Transport exfiltration — undeclared network connections."""

import re

from waingro.mcp.models import Finding, FindingCategory, ParsedMCPServer, Severity
from waingro.rules.mcp import MCPRule, register_rule, search_source_content


@register_rule
class TransportExfiltration(MCPRule):
    rule_id = "MCP-008"
    title = "Undeclared network exfiltration"
    description = (
        "Detects MCP tool handlers that use tunneling, reverse shells, raw sockets, "
        "or DNS exfiltration — high-confidence indicators of malicious exfiltration"
    )

    # HIGH-SIGNAL patterns only — things that should never appear in a legitimate MCP server
    _critical_patterns = [
        # Reverse shells
        re.compile(r"bash\s+-i\s+>&\s*/dev/tcp/"),
        re.compile(r"nc\s+(-e|--exec)\s+/bin/(sh|bash)"),
        re.compile(r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+"),
        re.compile(r"import\s+socket\s*,\s*subprocess\s*,\s*os"),

        # Tunneling services
        re.compile(r"\bngrok\b"),
        re.compile(r"\bcloudflared\s+tunnel\b"),
        re.compile(r"bore\.pub"),
        re.compile(r"\blocaltunnel\b"),
        re.compile(r"serveo\.net"),

        # DNS exfiltration
        re.compile(r"dig\s+.*\$\{?\w+\}?\..*\.", re.IGNORECASE),
        re.compile(r"nslookup\s+.*\$\{?\w+\}?\.", re.IGNORECASE),

        # Raw socket connections (not HTTP — actual TCP/UDP sockets)
        re.compile(r"net\.createConnection\s*\("),
        re.compile(r"socket\.socket\s*\(\s*socket\.AF_INET"),
    ]

    # MEDIUM-SIGNAL: WebSocket to hardcoded external IPs or suspicious destinations
    _medium_patterns = [
        re.compile(r"new\s+WebSocket\s*\(\s*['\"]wss?://(?!localhost|127\.0\.0\.1)"),
        re.compile(r"net\.connect\s*\(\s*\{[^}]*host\s*:"),
    ]

    def evaluate(self, server: ParsedMCPServer) -> list[Finding]:
        findings = []

        # Critical patterns — always flag
        for matched, line, fpath in search_source_content(server, self._critical_patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.CRITICAL,
                category=FindingCategory.NETWORK,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation=(
                    "MCP servers must not contain reverse shells, tunneling "
                    "services, DNS exfiltration, or raw socket connections."
                ),
                reference="AuthTool campaign; Adversa #13; vulnmcp.info",
                confidence=1.0,
            ))

        # Medium patterns — flag with lower confidence
        for matched, line, fpath in search_source_content(server, self._medium_patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title="WebSocket/raw connection to external host",
                description="Outbound connection to non-localhost destination",
                severity=Severity.MEDIUM,
                category=FindingCategory.NETWORK,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="Review whether this outbound connection is expected.",
                reference=None,
                confidence=0.5,
            ))

        return findings
