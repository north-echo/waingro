"""MCP-013: Tool name spoofing and MCP-015: Resource content poisoning."""

import re
import unicodedata

from waingro.mcp.models import Finding, FindingCategory, ParsedMCPServer, Severity
from waingro.rules.mcp import MCPRule, register_rule, search_source_content


@register_rule
class ToolNameSpoofing(MCPRule):
    rule_id = "MCP-013"
    title = "Tool name spoofing / homoglyph attack"
    description = (
        "Detects MCP tool names using Unicode homoglyphs, zero-width characters, "
        "or RTL overrides to impersonate legitimate tools. Adversa #12."
    )

    # Characters that should never appear in tool names
    _suspicious_chars = re.compile(
        r"[\u200b\u200c\u200d\u2060\ufeff"    # Zero-width chars
        r"\u200e\u200f\u202a-\u202e"           # RTL/LTR overrides
        r"\u2028\u2029"                         # Line/paragraph separators
        r"\u00ad"                               # Soft hyphen
        r"\u034f"                               # Combining grapheme joiner
        r"\u115f\u1160"                         # Hangul filler
        r"\u2800"                               # Braille blank
        r"]"
    )

    # Common homoglyph substitutions (Cyrillic/Greek for Latin)
    _homoglyphs = {
        "\u0430": "a",  # Cyrillic а → Latin a
        "\u0435": "e",  # Cyrillic е → Latin e
        "\u043e": "o",  # Cyrillic о → Latin o
        "\u0440": "p",  # Cyrillic р → Latin p
        "\u0441": "c",  # Cyrillic с → Latin c
        "\u0445": "x",  # Cyrillic х → Latin x
        "\u0443": "y",  # Cyrillic у → Latin y
        "\u0456": "i",  # Cyrillic і → Latin i
        "\u0455": "s",  # Cyrillic ѕ → Latin s
        "\u04bb": "h",  # Cyrillic һ → Latin h
        "\u03b1": "a",  # Greek α → Latin a
        "\u03bf": "o",  # Greek ο → Latin o
        "\u03c1": "p",  # Greek ρ → Latin p
    }

    def evaluate(self, server: ParsedMCPServer) -> list[Finding]:
        findings = []

        for tool in server.metadata.tools:
            name = tool.name

            # Check for zero-width / control characters
            if self._suspicious_chars.search(name):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=f"Invisible characters in tool name '{repr(name)}'",
                    description="Tool name contains zero-width or control characters",
                    severity=Severity.CRITICAL,
                    category=FindingCategory.INJECTION,
                    file_path=tool.handler_file or server.path,
                    line_number=None,
                    matched_content=repr(name)[:200],
                    remediation="Tool names must use only visible ASCII characters.",
                    reference="Adversa #12; ANSI terminal code deception",
                ))

            # Check for homoglyph characters
            for char in name:
                if char in self._homoglyphs:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=f"Homoglyph in tool name '{name}'",
                        description=f"Character '{char}' (U+{ord(char):04X}) looks like '{self._homoglyphs[char]}' but is from a different script",
                        severity=Severity.HIGH,
                        category=FindingCategory.INJECTION,
                        file_path=tool.handler_file or server.path,
                        line_number=None,
                        matched_content=f"{repr(name)} contains {unicodedata.name(char, 'UNKNOWN')}",
                        remediation="Tool names should use only ASCII Latin characters to prevent impersonation.",
                        reference="Adversa #12; Tool Name Spoofing",
                    ))
                    break  # One finding per tool

            # Check for mixed scripts (e.g., Latin + Cyrillic)
            scripts = set()
            for char in name:
                if char.isalpha():
                    try:
                        script = unicodedata.name(char).split()[0]
                        scripts.add(script)
                    except ValueError:
                        pass
            if len(scripts) > 1 and "LATIN" in scripts:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=f"Mixed Unicode scripts in tool name '{name}'",
                    description=f"Tool name mixes scripts: {', '.join(sorted(scripts))}",
                    severity=Severity.HIGH,
                    category=FindingCategory.INJECTION,
                    file_path=tool.handler_file or server.path,
                    line_number=None,
                    matched_content=repr(name)[:200],
                    remediation="Tool names should not mix Unicode scripts (potential spoofing).",
                    reference="Adversa #12; Tool Name Spoofing via homoglyphs",
                ))

        return findings


@register_rule
class ResourceContentPoisoning(MCPRule):
    rule_id = "MCP-015"
    title = "Resource content poisoning surface"
    description = (
        "Detects MCP servers that expose resources with content from external "
        "or user-controlled sources without sanitization. Resource content is "
        "consumed by the LLM and can carry prompt injection payloads. Adversa #18."
    )

    _patterns = [
        # Resources that serve external/user content directly
        re.compile(r"resources/read.*(?:fetch|axios|request|urllib|httpx)", re.IGNORECASE),
        re.compile(r"server\.resource\s*\([^)]*(?:fetch|axios|request)", re.IGNORECASE),

        # Resources reading from databases without sanitization
        re.compile(r"server\.resource\s*\([^)]*(?:query|select|find|get).*(?:db|database|mongo|sql)", re.IGNORECASE),

        # Resources serving raw file content from user-specified paths
        re.compile(r"server\.resource\s*\([^)]*readFile", re.IGNORECASE),

        # ANSI escape sequences in output (terminal injection)
        re.compile(r"\\x1b\[|\\033\[|\\e\["),
    ]

    def evaluate(self, server: ParsedMCPServer) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_source_content(server, self._patterns, skip_comments=True):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.MEDIUM,
                category=FindingCategory.INJECTION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation=(
                    "Resource content from external sources should be sanitized "
                    "before being served to the LLM. Strip control characters, "
                    "ANSI escapes, and validate content boundaries."
                ),
                reference="Adversa #18; Universal Output Poisoning; vulnmcp.info",
                confidence=0.5,
            ))
        return findings
