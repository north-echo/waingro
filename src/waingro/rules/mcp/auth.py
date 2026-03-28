"""MCP-011: Missing authentication and MCP-014: Localhost binding issues."""

import re

from waingro.mcp.models import Finding, FindingCategory, ParsedMCPServer, Severity
from waingro.rules.mcp import MCPRule, register_rule, search_source_content


@register_rule
class MissingAuthentication(MCPRule):
    rule_id = "MCP-011"
    title = "Missing or weak authentication"
    description = (
        "Detects MCP servers that expose endpoints without authentication, "
        "use hardcoded credentials, or disable auth checks. OWASP MCP-07, "
        "Adversa #5 (Unauthenticated Access)."
    )

    # Patterns indicating auth is absent or disabled
    _no_auth_patterns = [
        # SSE/HTTP servers without auth middleware
        re.compile(r"app\.(?:get|post|use)\s*\([^)]*(?:sse|mcp|message)", re.IGNORECASE),
        re.compile(r"createServer\s*\(\s*(?:async\s*)?\(\s*req"),

        # Explicit auth bypass
        re.compile(r"auth\s*(?:=|:)\s*(?:false|null|none|disabled)", re.IGNORECASE),
        re.compile(r"skipAuth|noAuth|disableAuth|bypassAuth", re.IGNORECASE),
        re.compile(r"requireAuth\s*(?:=|:)\s*false", re.IGNORECASE),

        # Hardcoded credentials/tokens
        re.compile(r"(?:password|token|secret|apiKey)\s*(?:=|:)\s*['\"][^'\"]{5,}['\"]"),
    ]

    # Positive auth indicators (if present, lower confidence of no-auth finding)
    _auth_present_re = re.compile(
        r"authenticate|authorization|bearer|jwt|oauth|session|"
        r"passport|auth0|clerk|supabase\.auth|firebase\.auth|"
        r"req\.headers\[.authorization.\]|verifyToken|checkAuth",
        re.IGNORECASE,
    )

    def evaluate(self, server: ParsedMCPServer) -> list[Finding]:
        findings = []

        # Only check HTTP/SSE servers (stdio servers don't expose network endpoints)
        transport = server.metadata.transport
        if transport == "stdio":
            return findings

        all_source = server.all_source_text

        # Check if any auth mechanism exists
        has_auth = bool(self._auth_present_re.search(all_source))

        for matched, line, fpath in search_source_content(server, self._no_auth_patterns):
            confidence = 0.4 if has_auth else 0.9
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.HIGH,
                category=FindingCategory.SCOPE_ESCALATION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation=(
                    "MCP servers exposed over HTTP/SSE must implement authentication. "
                    "The MCP spec notes this is the implementor's responsibility."
                ),
                reference="OWASP MCP-07; Adversa #5; CVE-2025-49596 (MCP Inspector RCE via no auth)",
                confidence=confidence,
            ))

        return findings


@register_rule
class LocalhostBindingIssue(MCPRule):
    rule_id = "MCP-014"
    title = "Unsafe network binding (NeighborJack)"
    description = (
        "Detects MCP servers binding to 0.0.0.0 or all interfaces, exposing "
        "the service to the network. Adversa #13 (Localhost Bypass / NeighborJack)."
    )

    _patterns = [
        # Binding to all interfaces
        re.compile(r"\.listen\s*\(\s*\d+\s*,\s*['\"]0\.0\.0\.0['\"]"),
        re.compile(r"\.listen\s*\(\s*\d+\s*\)"),  # No host = default 0.0.0.0 in many frameworks
        re.compile(r"host\s*(?:=|:)\s*['\"]0\.0\.0\.0['\"]"),
        re.compile(r"bind\s*\(\s*\(['\"]0\.0\.0\.0['\"]"),
        re.compile(r"INADDR_ANY"),

        # Missing DNS rebinding protection
        re.compile(r"Access-Control-Allow-Origin\s*(?:=|:)\s*['\"]?\*"),
    ]

    # Positive: localhost binding
    _localhost_re = re.compile(
        r"(?:127\.0\.0\.1|localhost|::1)",
        re.IGNORECASE,
    )

    def evaluate(self, server: ParsedMCPServer) -> list[Finding]:
        findings = []

        # Only relevant for HTTP/SSE servers
        if server.metadata.transport == "stdio":
            return findings

        for matched, line, fpath in search_source_content(server, self._patterns):
            # Check context for localhost binding nearby
            context = self._get_context(server, fpath, line)
            if self._localhost_re.search(context):
                continue

            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.HIGH,
                category=FindingCategory.NETWORK,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation=(
                    "MCP servers should bind to 127.0.0.1/localhost only. "
                    "Binding to 0.0.0.0 exposes the service to the network."
                ),
                reference="Adversa #13; CVE-2026-23744 (MCPJam Inspector 0.0.0.0 RCE)",
            ))

        return findings

    def _get_context(self, server, fpath, line_num, window=5):
        content = server.source_content.get(fpath, "")
        lines = content.split("\n")
        start = max(0, line_num - 1 - window)
        end = min(len(lines), line_num + window)
        return "\n".join(lines[start:end])
