"""Rule base class and registry for WAINGRO-MCP."""

import re
from abc import ABC, abstractmethod
from pathlib import Path

from waingro.mcp.models import Finding, ParsedMCPServer

_RULES: list[type["MCPRule"]] = []


class MCPRule(ABC):
    """Base class for all MCP detection rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique rule identifier, e.g. MCP-001"""

    @property
    @abstractmethod
    def title(self) -> str:
        """Human-readable rule name"""

    @property
    @abstractmethod
    def description(self) -> str:
        """What this rule detects"""

    @abstractmethod
    def evaluate(self, server: ParsedMCPServer) -> list[Finding]:
        """Run the rule against a parsed MCP server. Return findings."""


def register_rule(cls: type[MCPRule]) -> type[MCPRule]:
    """Decorator to register a rule class."""
    _RULES.append(cls)
    return cls


def get_all_rules() -> list[MCPRule]:
    """Instantiate and return all registered rules."""
    return [cls() for cls in _RULES]


# --- Shared search utilities ---

_COMMENT_RE = re.compile(r"^\s*#(?!!)")
_JS_COMMENT_RE = re.compile(r"^\s*//")
_STRING_CONTEXT_RE = re.compile(
    r"""(?:die|echo|print|printf|warn|error|log|msg|message|usage|help)\s*[("]\s*.*$""",
    re.IGNORECASE,
)

SCRIPT_EXTENSIONS = {".sh", ".bash", ".zsh", ".py", ".js", ".ts", ".mjs", ".cjs"}


def _is_non_executable_line(line: str, file_path: Path | None = None) -> bool:
    """Check if a line is a comment or string-literal context."""
    if file_path and file_path.suffix in SCRIPT_EXTENSIONS:
        stripped = line.lstrip()
        if _COMMENT_RE.match(stripped):
            return True
        if file_path.suffix in (".js", ".ts", ".mjs", ".cjs") and _JS_COMMENT_RE.match(stripped):
            return True
    return bool(_STRING_CONTEXT_RE.match(line.lstrip()))


def search_source_content(
    server: ParsedMCPServer,
    patterns: list[re.Pattern],
    skip_comments: bool = True,
) -> list[tuple[str, int, Path]]:
    """Search all source files for pattern matches.

    Returns (matched_text, line_number, file_path) tuples.
    """
    hits: list[tuple[str, int, Path]] = []
    for fpath, content in server.source_content.items():
        for i, line in enumerate(content.split("\n"), start=1):
            if skip_comments and _is_non_executable_line(line, fpath):
                continue
            for pat in patterns:
                m = pat.search(line)
                if m:
                    hits.append((m.group(0), i, fpath))
    return hits


def search_tool_definitions(
    server: ParsedMCPServer,
    patterns: list[re.Pattern],
) -> list[tuple[str, int | None, Path, str]]:
    """Search MCP tool descriptions and parameter schemas for patterns.

    Returns (matched_text, line_number, file_path, tool_name) tuples.
    """
    hits: list[tuple[str, int | None, Path, str]] = []
    for tool in server.metadata.tools:
        # Search tool description
        for pat in patterns:
            m = pat.search(tool.description)
            if m:
                fpath = tool.handler_file or server.path
                hits.append((m.group(0), None, fpath, tool.name))

        # Search parameter descriptions and defaults
        params = tool.parameters
        if isinstance(params, dict):
            _search_param_dict(params, patterns, tool, server.path, hits)

    return hits


def _search_param_dict(
    d: dict,
    patterns: list[re.Pattern],
    tool,
    server_path: Path,
    hits: list,
) -> None:
    """Recursively search parameter schema dicts for pattern matches."""
    for key, value in d.items():
        if isinstance(value, str):
            for pat in patterns:
                m = pat.search(value)
                if m:
                    fpath = tool.handler_file or server_path
                    hits.append((m.group(0), None, fpath, tool.name))
        elif isinstance(value, dict):
            _search_param_dict(value, patterns, tool, server_path, hits)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    for pat in patterns:
                        m = pat.search(item)
                        if m:
                            fpath = tool.handler_file or server_path
                            hits.append((m.group(0), None, fpath, tool.name))
                elif isinstance(item, dict):
                    _search_param_dict(item, patterns, tool, server_path, hits)
