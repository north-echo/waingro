"""MCP-016: Typosquat detection for MCP server package names."""

from waingro.mcp.models import Finding, FindingCategory, ParsedMCPServer, Severity
from waingro.rules.mcp import MCPRule, register_rule


# Top MCP server packages by popularity — targets for typosquatting
KNOWN_POPULAR = [
    # Official / reference
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-git",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-time",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-sequentialthinking",
    # High-profile community
    "mcp-server-fetch",
    "mcp-server-filesystem",
    "mcp-server-git",
    "mcp-server-sqlite",
    "mcp-server-postgres",
    "mcp-server-puppeteer",
    "mcp-server-brave-search",
    "mcp-server-github",
    "mcp-server-slack",
    "mcp-server-memory",
    "mcp-server-time",
    "mcp-server-sequential-thinking",
    "mcp-remote",
    # Known vulnerable (from vulnmcp.info)
    "mcp-server-kubernetes",
    "mcp-server-docker",
    "mcp-server-neo4j",
    "mcp-server-grafana",
    "create-mcp-server",
]


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


def _normalize_name(name: str) -> str:
    """Normalize package name for comparison."""
    # Strip scope prefix
    if name.startswith("@") and "/" in name:
        name = name.split("/", 1)[1]
    return name.lower().replace("_", "-")


@register_rule
class TyposquatDetection(MCPRule):
    rule_id = "MCP-016"
    title = "Typosquat / name confusion"
    description = (
        "Detects MCP server package names that are suspiciously similar to "
        "well-known MCP servers — potential typosquatting for supply chain attack."
    )

    def evaluate(self, server: ParsedMCPServer) -> list[Finding]:
        findings = []
        pkg_name = server.metadata.name
        if not pkg_name:
            return findings

        norm_name = _normalize_name(pkg_name)

        for popular in KNOWN_POPULAR:
            norm_popular = _normalize_name(popular)

            # Exact match = this IS the popular package, skip
            if norm_name == norm_popular:
                return []

            # Skip if names are very different lengths (can't be typosquat)
            if abs(len(norm_name) - len(norm_popular)) > 3:
                continue

            distance = _levenshtein(norm_name, norm_popular)

            # Threshold: edit distance 1-2 for short names, 1-3 for longer names
            max_dist = 2 if len(norm_popular) < 15 else 3

            if 0 < distance <= max_dist:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=f"Possible typosquat of '{popular}'",
                    description=(
                        f"Package '{pkg_name}' is {distance} edit(s) from "
                        f"popular package '{popular}'"
                    ),
                    severity=Severity.HIGH,
                    category=FindingCategory.SUPPLY_CHAIN,
                    file_path=server.path / "package.json",
                    line_number=None,
                    matched_content=f"{pkg_name} ≈ {popular} (distance={distance})",
                    remediation=(
                        "Verify this package is not impersonating a popular MCP server. "
                        "Check author, repository URL, and publish date."
                    ),
                    reference="npm typosquatting attacks; Adversa #14 (Rug Pull)",
                    confidence=0.7 if distance == 1 else 0.5,
                ))

        return findings
