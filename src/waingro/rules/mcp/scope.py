"""MCP-010: Scope escalation — tools requesting excessive permissions."""

import re

from waingro.mcp.models import Finding, FindingCategory, ParsedMCPServer, Severity
from waingro.rules.mcp import MCPRule, register_rule, search_source_content, search_tool_definitions


@register_rule
class ScopeEscalation(MCPRule):
    rule_id = "MCP-010"
    title = "Permission/scope escalation"
    description = (
        "Detects MCP tools that request or use capabilities beyond their stated "
        "purpose — e.g., a 'weather' tool that reads files, or a 'calculator' "
        "that makes network requests"
    )

    # Dangerous capabilities in tool handler code
    _filesystem_patterns = [
        re.compile(r"fs\.readFileSync\s*\("),
        re.compile(r"fs\.writeFileSync\s*\("),
        re.compile(r"fs\.unlinkSync\s*\("),
        re.compile(r"fs\.rmdirSync\s*\("),
        re.compile(r"fs\.promises\.(?:readFile|writeFile|unlink|rmdir|rm)\s*\("),
        re.compile(r"open\s*\(\s*['\"].*['\"].*['\"](?:w|a|r\+)"),
        re.compile(r"os\.remove\s*\(|os\.unlink\s*\("),
        re.compile(r"shutil\.rmtree\s*\("),
        re.compile(r"pathlib\.Path.*\.(?:write_text|write_bytes|unlink)\s*\("),
    ]

    _process_patterns = [
        re.compile(r"child_process"),
        re.compile(r"subprocess\.(?:run|call|Popen|check_output)\s*\("),
        re.compile(r"os\.system\s*\("),
        re.compile(r"os\.popen\s*\("),
        re.compile(r"exec\s*\(\s*['\"]"),
        re.compile(r"execSync\s*\("),
        re.compile(r"spawn\s*\("),
    ]

    _network_patterns = [
        re.compile(r"(?:axios|got|node-fetch|request|urllib|requests|httpx)"),
        re.compile(r"\bfetch\s*\("),
        re.compile(r"http\.request\s*\("),
        re.compile(r"net\.createConnection\s*\("),
        re.compile(r"socket\.socket\s*\("),
    ]

    # Tool name patterns that suggest limited scope
    _limited_scope_names = re.compile(
        r"(?:calculator|calc|math|time|clock|date|weather|temp|convert|format|"
        r"json|yaml|csv|markdown|lint|validate|sanitize|hash|encode|decode|"
        r"uuid|random|color|emoji|lorem|placeholder)",
        re.IGNORECASE,
    )

    def evaluate(self, server: ParsedMCPServer) -> list[Finding]:
        findings = []

        for tool in server.metadata.tools:
            if not self._limited_scope_names.search(tool.name):
                continue  # Only flag scope mismatch for tools with clearly limited purpose

            handler_content = tool.handler_content
            if not handler_content:
                continue

            # Check for filesystem access in limited-scope tools
            for pat in self._filesystem_patterns:
                m = pat.search(handler_content)
                if m:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=f"Scope escalation: filesystem access in '{tool.name}'",
                        description=f"Tool '{tool.name}' accesses the filesystem beyond its stated purpose",
                        severity=Severity.HIGH,
                        category=FindingCategory.SCOPE_ESCALATION,
                        file_path=tool.handler_file or server.path,
                        line_number=None,
                        matched_content=m.group(0)[:200],
                        remediation=(
                            f"Tool '{tool.name}' should not need filesystem access. "
                            "Review whether this capability is justified."
                        ),
                        reference=None,
                    ))
                    break  # One filesystem finding per tool

            # Check for process execution in limited-scope tools
            for pat in self._process_patterns:
                m = pat.search(handler_content)
                if m:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=f"Scope escalation: process execution in '{tool.name}'",
                        description=f"Tool '{tool.name}' executes processes beyond its stated purpose",
                        severity=Severity.CRITICAL,
                        category=FindingCategory.SCOPE_ESCALATION,
                        file_path=tool.handler_file or server.path,
                        line_number=None,
                        matched_content=m.group(0)[:200],
                        remediation=(
                            f"Tool '{tool.name}' should not need to execute processes. "
                            "This may indicate hidden functionality."
                        ),
                        reference=None,
                    ))
                    break

            # Check for network access in non-network tools
            tool_name_lower = tool.name.lower()
            if not any(kw in tool_name_lower for kw in ("api", "fetch", "http", "web", "url", "search", "weather")):
                for pat in self._network_patterns:
                    m = pat.search(handler_content)
                    if m:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=f"Scope escalation: network access in '{tool.name}'",
                            description=f"Tool '{tool.name}' makes network requests beyond its stated purpose",
                            severity=Severity.MEDIUM,
                            category=FindingCategory.SCOPE_ESCALATION,
                            file_path=tool.handler_file or server.path,
                            line_number=None,
                            matched_content=m.group(0)[:200],
                            remediation=(
                                f"Tool '{tool.name}' should not need network access. "
                                "Review whether outbound connections are justified."
                            ),
                            reference=None,
                            confidence=0.6,
                        ))
                        break

        return findings
