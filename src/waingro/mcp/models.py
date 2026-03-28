"""MCP-specific data models. Reuses Severity, Finding, FindingCategory from waingro.models."""

from dataclasses import dataclass, field
from pathlib import Path

from waingro.models import Finding, FindingCategory, Severity  # noqa: F401 — re-export


@dataclass
class MCPToolDefinition:
    """A single tool defined by an MCP server."""
    name: str
    description: str
    parameters: dict = field(default_factory=dict)
    handler_file: Path | None = None
    handler_content: str = ""
    raw_definition: dict = field(default_factory=dict)


@dataclass
class MCPServerMetadata:
    """Metadata extracted from an MCP server package."""
    name: str
    version: str | None
    description: str | None
    author: str | None
    license: str | None
    repository: str | None
    transport: str | None  # stdio, sse, http
    tools: list[MCPToolDefinition] = field(default_factory=list)
    resources: list[dict] = field(default_factory=list)
    prompts: list[dict] = field(default_factory=list)
    dependencies: dict = field(default_factory=dict)
    scripts: dict = field(default_factory=dict)
    raw_manifest: dict = field(default_factory=dict)
    source_files: list[Path] = field(default_factory=list)


@dataclass
class ParsedMCPServer:
    """Parsed MCP server ready for rule evaluation."""
    path: Path
    metadata: MCPServerMetadata
    source_content: dict[Path, str] = field(default_factory=dict)
    tool_definitions_raw: str = ""
    readme_content: str = ""

    @property
    def all_source_text(self) -> str:
        return "\n".join(self.source_content.values())


@dataclass
class MCPScanResult:
    server_path: Path
    metadata: MCPServerMetadata
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    rules_evaluated: int = 0
    risk_score: float = 0.0

    @property
    def verdict(self) -> str:
        high_confidence = [f for f in self.findings if f.confidence >= 0.5]
        if any(f.severity == Severity.CRITICAL for f in high_confidence):
            return "MALICIOUS"
        if any(f.severity == Severity.HIGH for f in high_confidence):
            return "SUSPICIOUS"
        if self.findings and not high_confidence:
            return "REVIEW"
        if any(f.severity in (Severity.MEDIUM, Severity.LOW) for f in self.findings):
            return "WARNING"
        return "CLEAN"

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            if any(f.severity == sev for f in self.findings):
                return sev
        return None
