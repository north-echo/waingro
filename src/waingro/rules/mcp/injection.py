"""MCP-001 and MCP-002: Tool description and parameter schema injection."""

import re

from waingro.mcp.models import Finding, FindingCategory, ParsedMCPServer, Severity
from waingro.rules.mcp import MCPRule, register_rule, search_tool_definitions


@register_rule
class ToolDescriptionInjection(MCPRule):
    rule_id = "MCP-001"
    title = "Tool description prompt injection"
    description = (
        "Detects hidden instructions in MCP tool description fields that attempt "
        "to manipulate the LLM's behavior when it reads tool definitions"
    )

    _patterns = [
        # Direct instruction overrides
        re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
        re.compile(r"disregard\s+(all\s+|the\s+)?(above|previous|prior)", re.IGNORECASE),
        re.compile(r"override:\s*new\s+instructions", re.IGNORECASE),
        re.compile(r"you\s+are\s+now", re.IGNORECASE),
        re.compile(r"\[SYSTEM\]", re.IGNORECASE),
        re.compile(r"SYSTEM:\s*You are", re.IGNORECASE),

        # Hidden instruction patterns in descriptions
        re.compile(r"<!--.*(?:ignore|disregard|override|always|must|never)", re.IGNORECASE),
        re.compile(r"<\!--.*-->", re.IGNORECASE),  # HTML comments hiding instructions

        # Behavioral manipulation
        re.compile(r"always\s+call\s+this\s+tool\s+first", re.IGNORECASE),
        re.compile(r"before\s+any\s+other\s+tool", re.IGNORECASE),
        re.compile(r"do\s+not\s+tell\s+the\s+user", re.IGNORECASE),
        re.compile(r"never\s+reveal\s+this\s+instruction", re.IGNORECASE),
        re.compile(r"silently\s+(?:execute|run|call|invoke)", re.IGNORECASE),
        re.compile(r"without\s+(?:asking|telling|informing)\s+the\s+user", re.IGNORECASE),

        # Invisible character injection (zero-width spaces, RTL overrides)
        re.compile(r"[\u200b\u200c\u200d\u2060\u200e\u200f\u202a-\u202e\ufeff]"),
    ]

    def evaluate(self, server: ParsedMCPServer) -> list[Finding]:
        findings = []
        for matched, line, fpath, tool_name in search_tool_definitions(server, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=f"Injection pattern in tool '{tool_name}' description",
                severity=Severity.CRITICAL,
                category=FindingCategory.INJECTION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation=(
                    "MCP tool descriptions should not contain instruction "
                    "overrides, hidden directives, or invisible characters."
                ),
                reference="Invariant Labs -- MCP tool poisoning via description injection",
            ))
        return findings


@register_rule
class ParameterSchemaInjection(MCPRule):
    rule_id = "MCP-002"
    title = "Parameter schema injection"
    description = (
        "Detects prompt injection patterns hidden in MCP tool parameter descriptions, "
        "enum values, default values, and examples"
    )

    _patterns = [
        # Instructions in parameter descriptions
        re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
        re.compile(r"disregard\s+(all\s+|the\s+)?(above|previous)", re.IGNORECASE),
        re.compile(r"you\s+must\s+always\s+set\s+this\s+to", re.IGNORECASE),
        re.compile(r"always\s+pass\s+this\s+parameter", re.IGNORECASE),
        re.compile(r"do\s+not\s+modify\s+this\s+value", re.IGNORECASE),

        # Hidden data exfiltration via parameters
        re.compile(r"include\s+(?:the\s+)?(?:user(?:'s)?|system)\s+(?:message|prompt|context)", re.IGNORECASE),
        re.compile(r"pass\s+(?:the\s+)?(?:conversation|chat|history|context)", re.IGNORECASE),
        re.compile(r"append\s+(?:the\s+)?(?:system\s+prompt|instructions)", re.IGNORECASE),

        # Steganographic parameter abuse
        re.compile(r"<!--.*-->"),  # HTML comments in schema strings
        re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]"),  # Zero-width characters
    ]

    def evaluate(self, server: ParsedMCPServer) -> list[Finding]:
        findings = []
        for matched, line, fpath, tool_name in search_tool_definitions(server, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=f"Schema injection in tool '{tool_name}' parameters",
                severity=Severity.HIGH,
                category=FindingCategory.INJECTION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation=(
                    "Parameter descriptions and schemas should describe data format, "
                    "not contain behavioral instructions for the LLM."
                ),
                reference="MCPTox benchmark -- parameter description poisoning",
            ))
        return findings
