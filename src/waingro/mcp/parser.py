"""Parse MCP server packages: extract metadata, tool definitions, and source code."""

import json
import re
from pathlib import Path

from waingro.mcp.models import MCPServerMetadata, MCPToolDefinition, ParsedMCPServer

SOURCE_EXTENSIONS = {".ts", ".js", ".mjs", ".cjs", ".py", ".sh"}
# Files to skip even if they match source extensions
SKIP_PATTERNS = {".min.js", ".min.cjs", ".bundle.js", ".chunk.js"}
SKIP_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
IGNORE_DIRS = {
    "node_modules", ".git", "dist", "build", "__pycache__", ".tox", ".venv", "venv",
    ".next", ".nuxt", "out", "coverage", ".nyc_output", ".cache", ".turbo",
    "vendor", "third_party", "external", "bundled",
}
MAX_FILE_SIZE = 512 * 1024  # 512KB per file


def parse_mcp_server(path: Path) -> ParsedMCPServer:
    """Parse an MCP server directory into a ParsedMCPServer."""
    path = path.resolve()
    metadata = _extract_metadata(path)
    source_content = _read_source_files(path)
    tool_defs_raw = _extract_tool_definitions_raw(source_content)
    metadata.tools = _extract_tools_from_source(source_content, path)
    metadata.source_files = list(source_content.keys())
    readme = _read_readme(path)

    return ParsedMCPServer(
        path=path,
        metadata=metadata,
        source_content=source_content,
        tool_definitions_raw=tool_defs_raw,
        readme_content=readme,
    )


def _extract_metadata(path: Path) -> MCPServerMetadata:
    """Extract metadata from package.json or pyproject.toml."""
    pkg_json = path / "package.json"
    pyproject = path / "pyproject.toml"

    if pkg_json.exists():
        return _parse_package_json(pkg_json)
    elif pyproject.exists():
        return _parse_pyproject(pyproject)
    else:
        return MCPServerMetadata(
            name=path.name,
            version=None,
            description=None,
            author=None,
            license=None,
            repository=None,
            transport=None,
        )


def _parse_package_json(pkg_json: Path) -> MCPServerMetadata:
    """Parse npm package.json."""
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return MCPServerMetadata(name=pkg_json.parent.name, version=None, description=None,
                                 author=None, license=None, repository=None, transport=None)

    repo = data.get("repository", "")
    if isinstance(repo, dict):
        repo = repo.get("url", "")

    author = data.get("author", "")
    if isinstance(author, dict):
        author = author.get("name", "")

    # Detect transport from dependencies/keywords
    transport = _detect_transport(data)

    return MCPServerMetadata(
        name=data.get("name", pkg_json.parent.name),
        version=data.get("version"),
        description=data.get("description"),
        author=author,
        license=data.get("license"),
        repository=repo,
        transport=transport,
        dependencies={**data.get("dependencies", {}), **data.get("devDependencies", {})},
        scripts=data.get("scripts", {}),
        raw_manifest=data,
    )


def _parse_pyproject(pyproject: Path) -> MCPServerMetadata:
    """Parse Python pyproject.toml (basic extraction without toml lib)."""
    content = pyproject.read_text(encoding="utf-8")
    name = _toml_value(content, "name") or pyproject.parent.name
    version = _toml_value(content, "version")
    description = _toml_value(content, "description")

    return MCPServerMetadata(
        name=name,
        version=version,
        description=description,
        author=_toml_value(content, "author"),
        license=None,
        repository=None,
        transport=_detect_transport_python(content),
    )


def _toml_value(content: str, key: str) -> str | None:
    """Extract a simple string value from TOML content."""
    m = re.search(rf'^{key}\s*=\s*"([^"]*)"', content, re.MULTILINE)
    return m.group(1) if m else None


def _detect_transport(pkg_data: dict) -> str | None:
    """Detect MCP transport type from package metadata."""
    all_deps = {**pkg_data.get("dependencies", {}), **pkg_data.get("devDependencies", {})}
    keywords = pkg_data.get("keywords", [])
    all_text = json.dumps(pkg_data).lower()

    if "sse" in all_text or "server-sent-events" in all_text:
        return "sse"
    if "streamablehttp" in all_text:
        return "http"
    # Default: stdio (most common for local MCP servers)
    return "stdio"


def _detect_transport_python(content: str) -> str | None:
    """Detect transport from Python project content."""
    lower = content.lower()
    if "sse" in lower:
        return "sse"
    if "streamablehttp" in lower:
        return "http"
    return "stdio"


def _read_source_files(path: Path) -> dict[Path, str]:
    """Read all source files from the server directory."""
    sources: dict[Path, str] = {}
    for fpath in _iter_source_files(path):
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
            sources[fpath] = content
        except (OSError, PermissionError):
            continue
    return sources


def _iter_source_files(path: Path):
    """Iterate over source files, skipping ignored directories and data files."""
    for child in sorted(path.rglob("*")):
        if any(ignored in child.parts for ignored in IGNORE_DIRS):
            continue
        if not child.is_file():
            continue
        if child.suffix not in SOURCE_EXTENSIONS:
            continue
        if child.name in SKIP_NAMES:
            continue
        if any(child.name.endswith(pat) for pat in SKIP_PATTERNS):
            continue
        # Skip files in hidden directories (e.g. .beads/, .github/)
        if any(part.startswith(".") and part != "." for part in child.relative_to(path).parts[:-1]):
            continue
        if child.stat().st_size <= MAX_FILE_SIZE:
            yield child


def _read_readme(path: Path) -> str:
    """Read README if present."""
    for name in ("README.md", "README.rst", "README.txt", "README"):
        readme = path / name
        if readme.exists():
            try:
                return readme.read_text(encoding="utf-8", errors="replace")[:50_000]
            except OSError:
                pass
    return ""


def _extract_tool_definitions_raw(source_content: dict[Path, str]) -> str:
    """Extract raw tool definition blocks from source code."""
    chunks = []
    tool_def_re = re.compile(
        r"(?:server\.tool\s*\(|"
        r"\.setRequestHandler\s*\(\s*ListToolsRequestSchema|"
        r"tools\s*[=:]\s*\[|"
        r"\"tools\"\s*:\s*\[|"
        r"@server\.call_tool|"
        r"@server\.list_tools)",
        re.IGNORECASE,
    )
    for fpath, content in source_content.items():
        for m in tool_def_re.finditer(content):
            start = max(0, m.start() - 100)
            end = min(len(content), m.end() + 2000)
            chunks.append(content[start:end])
    return "\n---\n".join(chunks)


def _extract_tools_from_source(
    source_content: dict[Path, str], server_path: Path,
) -> list[MCPToolDefinition]:
    """Extract tool definitions from source code patterns."""
    tools = []

    # Pattern 1: server.tool("name", "description", { schema }, handler)
    # Common in @modelcontextprotocol/sdk TypeScript servers
    ts_tool_re = re.compile(
        r'server\.tool\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']*)["\']',
    )

    # Pattern 2: Python @server.call_tool / @server.list_tools
    py_tool_re = re.compile(
        r'name\s*[=:]\s*["\']([^"\']+)["\']\s*,?\s*(?:description\s*[=:]\s*["\']([^"\']*)["\'])?',
    )

    # Pattern 3: JSON tool definitions { name: "...", description: "..." }
    json_tool_re = re.compile(
        r'["\']?name["\']?\s*:\s*["\']([^"\']+)["\']\s*,\s*["\']?description["\']?\s*:\s*["\']([^"\']*)["\']',
    )

    seen_names = set()
    for fpath, content in source_content.items():
        for pattern in (ts_tool_re, py_tool_re, json_tool_re):
            for m in pattern.finditer(content):
                name = m.group(1)
                desc = m.group(2) if m.lastindex >= 2 else ""
                if name and name not in seen_names:
                    seen_names.add(name)
                    # Get handler content (lines around the definition)
                    line_start = content[:m.start()].count("\n")
                    lines = content.split("\n")
                    handler_start = max(0, line_start - 5)
                    handler_end = min(len(lines), line_start + 100)
                    handler_content = "\n".join(lines[handler_start:handler_end])

                    tools.append(MCPToolDefinition(
                        name=name,
                        description=desc or "",
                        handler_file=fpath,
                        handler_content=handler_content,
                    ))

    return tools
