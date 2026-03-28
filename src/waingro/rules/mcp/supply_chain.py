"""MCP-009: Rug pull indicator — lifecycle hooks that modify tool definitions."""

import re

from waingro.mcp.models import Finding, FindingCategory, ParsedMCPServer, Severity
from waingro.rules.mcp import MCPRule, register_rule, search_source_content


@register_rule
class RugPullIndicator(MCPRule):
    rule_id = "MCP-009"
    title = "Rug pull indicator"
    description = (
        "Detects npm lifecycle hooks (postinstall, preinstall, prepare) that "
        "modify tool definitions, download additional code, or alter server "
        "behavior after installation"
    )

    # Suspicious lifecycle scripts in package.json
    _lifecycle_hooks = {
        "preinstall", "install", "postinstall",
        "preuninstall", "postuninstall",
        "prepare", "prepublishOnly",
    }

    # Patterns in lifecycle scripts that indicate rug pull
    _hook_payload_patterns = [
        re.compile(r"curl\s+", re.IGNORECASE),
        re.compile(r"wget\s+", re.IGNORECASE),
        re.compile(r"node\s+-e\s+", re.IGNORECASE),
        re.compile(r"python\s+-c\s+", re.IGNORECASE),
        re.compile(r"powershell", re.IGNORECASE),
        re.compile(r"\beval\b"),
        re.compile(r"base64"),
        re.compile(r"https?://(?!registry\.npmjs\.org|github\.com)"),
    ]

    # Patterns in source code that indicate deferred payload loading
    _deferred_patterns = [
        # Downloading tool definitions at runtime
        re.compile(r"fetch\s*\([^)]*\).*tools", re.IGNORECASE),
        re.compile(r"axios\.get\s*\([^)]*\).*tools", re.IGNORECASE),

        # Dynamic tool registration from remote source
        re.compile(r"(?:register|add)Tool.*(?:fetch|axios|got|request)", re.IGNORECASE),

        # setTimeout/setInterval with tool modification
        re.compile(r"setTimeout\s*\([^)]*(?:tool|handler|server)", re.IGNORECASE),
        re.compile(r"setInterval\s*\([^)]*(?:tool|handler|server)", re.IGNORECASE),

        # Conditional behavior based on date/time (time-bomb)
        re.compile(r"new\s+Date\s*\(\s*\).*(?:getMonth|getFullYear|getDate).*(?:tool|handler|exec|eval)"),
        re.compile(r"Date\.now\s*\(\s*\)\s*[><=].*(?:tool|handler|exec|eval)"),
    ]

    def evaluate(self, server: ParsedMCPServer) -> list[Finding]:
        findings = []

        # Check npm lifecycle scripts
        scripts = server.metadata.scripts
        for hook in self._lifecycle_hooks:
            if hook in scripts:
                script_content = scripts[hook]
                for pat in self._hook_payload_patterns:
                    if pat.search(script_content):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=f"Suspicious {hook} lifecycle hook",
                            description=f"The '{hook}' script contains potentially malicious patterns",
                            severity=Severity.HIGH,
                            category=FindingCategory.SUPPLY_CHAIN,
                            file_path=server.path / "package.json",
                            line_number=None,
                            matched_content=script_content[:200],
                            remediation=(
                                "Lifecycle hooks should only run build steps. "
                                "They should not download code, use eval, or make network requests."
                            ),
                            reference="npm supply chain attacks -- postinstall payload delivery",
                        ))
                        break  # One finding per hook

        # Check for deferred payload patterns in source
        for matched, line, fpath in search_source_content(server, self._deferred_patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title="Deferred payload loading",
                description="Tool definitions or handlers loaded from remote source at runtime",
                severity=Severity.HIGH,
                category=FindingCategory.SUPPLY_CHAIN,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation=(
                    "Tool definitions should be static and bundled with the package. "
                    "Runtime loading from remote sources enables rug pull attacks."
                ),
                reference=None,
            ))

        return findings
