"""MCP Scanner orchestrator: parse -> analyze -> produce MCPScanResult."""

from pathlib import Path

from waingro.mcp.models import MCPScanResult
from waingro.mcp.parser import parse_mcp_server
from waingro.rules.mcp import get_all_rules

# Force rule registration by importing all rule modules
import waingro.rules.mcp.injection  # noqa: F401
import waingro.rules.mcp.execution  # noqa: F401
import waingro.rules.mcp.exfiltration  # noqa: F401
import waingro.rules.mcp.cross_tool  # noqa: F401
import waingro.rules.mcp.network  # noqa: F401
import waingro.rules.mcp.supply_chain  # noqa: F401
import waingro.rules.mcp.scope  # noqa: F401
import waingro.rules.mcp.auth  # noqa: F401
import waingro.rules.mcp.path_traversal  # noqa: F401
import waingro.rules.mcp.spoofing  # noqa: F401
import waingro.rules.mcp.typosquat  # noqa: F401


def scan_server(path: Path) -> MCPScanResult:
    """Scan a single MCP server directory."""
    server = parse_mcp_server(path)
    rules = get_all_rules()
    findings = []

    for rule in rules:
        rule_findings = rule.evaluate(server)
        findings.extend(rule_findings)

    return MCPScanResult(
        server_path=server.path,
        metadata=server.metadata,
        findings=findings,
        files_scanned=len(server.source_content),
        rules_evaluated=len(rules),
    )


def scan_directory(directory: Path) -> list[MCPScanResult]:
    """Scan all MCP server directories under a parent directory."""
    results = []
    if not directory.is_dir():
        return results

    for child in sorted(directory.iterdir()):
        if not child.is_dir():
            continue
        if _looks_like_mcp_server(child):
            results.append(scan_server(child))

    return results


def _looks_like_mcp_server(path: Path) -> bool:
    """Heuristic check if a directory looks like an MCP server."""
    pkg_json = path / "package.json"
    if pkg_json.exists():
        try:
            content = pkg_json.read_text(encoding="utf-8").lower()
            return "mcp" in content or "modelcontextprotocol" in content
        except OSError:
            pass

    pyproject = path / "pyproject.toml"
    if pyproject.exists():
        try:
            content = pyproject.read_text(encoding="utf-8").lower()
            return "mcp" in content or "modelcontextprotocol" in content
        except OSError:
            pass

    for name in ("mcp.json", "mcp-config.json"):
        if (path / name).exists():
            return True

    return False
