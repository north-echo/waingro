"""Data models for WAINGRO scan results."""

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(StrEnum):
    EXECUTION = "execution"
    EXFILTRATION = "exfiltration"
    PERSISTENCE = "persistence"
    NETWORK = "network"
    OBFUSCATION = "obfuscation"
    INJECTION = "injection"
    SOCIAL_ENGINEERING = "social-engineering"
    TYPOSQUATTING = "typosquatting"
    BEHAVIORAL_MISMATCH = "behavioral-mismatch"
    # MCP-specific categories
    SUPPLY_CHAIN = "supply-chain"
    SCOPE_ESCALATION = "scope-escalation"
    CROSS_TOOL = "cross-tool"


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: FindingCategory
    file_path: Path
    line_number: int | None
    matched_content: str
    remediation: str
    reference: str | None
    confidence: float = 1.0
    context_note: str | None = None


@dataclass
class SkillMetadata:
    name: str
    description: str | None
    version: str | None
    author: str | None
    tags: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    raw_frontmatter: dict = field(default_factory=dict)


@dataclass
class BundledFileContent:
    """Content of a bundled script file with its path."""

    path: Path
    content: str


@dataclass
class ParsedSkill:
    path: Path
    metadata: SkillMetadata
    body: str
    code_blocks: list[dict] = field(default_factory=list)
    bundled_files: list[Path] = field(default_factory=list)
    bundled_content: list[BundledFileContent] = field(default_factory=list)
    sections: list = field(default_factory=list)  # list[MarkdownSection]
    frontmatter_lines: int = 0  # lines consumed by YAML frontmatter, for line-number offset


@dataclass
class ScanResult:
    skill_path: Path
    metadata: SkillMetadata
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    rules_evaluated: int = 0
    security_tool_score: float = 0.0
    risk_profile: dict = field(default_factory=dict)

    @property
    def verdict(self) -> str:
        """Classify evidence without treating severity as proof of intent.

        A critical primitive such as ``curl | bash`` is dangerous, but it is
        not by itself enough to call an author malicious. MALICIOUS is reserved
        for a near-unambiguous attack primitive or corroborating high-confidence
        evidence across multiple attack stages. Probable security scanners are
        routed to REVIEW so their signature libraries do not become accusations.
        """
        high_confidence = [f for f in self.findings if f.confidence >= 0.5]
        if self.findings and not high_confidence:
            return "REVIEW"
        # DNS exfiltration already proves a source-bearing value reaches a
        # covert network sink. A reverse-shell string alone can still be a
        # tutorial, detection signature, or blocked example, so NET-001 stays
        # visible as SUSPICIOUS unless another same-file attack stage confirms it.
        direct_attack_rules = {"NET-004"}
        if any(
            f.rule_id in direct_attack_rules and f.severity == Severity.CRITICAL
            for f in high_confidence
        ):
            return "MALICIOUS"

        critical = [f for f in high_confidence if f.severity == Severity.CRITICAL]
        rules_by_file: dict[str, set[str]] = {}
        for finding in high_confidence:
            rules_by_file.setdefault(str(finding.file_path), set()).add(finding.rule_id)

        encoded_execution = {"EXEC-002", "OBFUSC-001"}
        c2_execution = {"EXEC-001", "EXEC-006", "EXEC-009"}
        if critical and any(
            encoded_execution <= rules
            or ("NET-002" in rules and bool(rules & c2_execution))
            for rules in rules_by_file.values()
        ):
            return "MALICIOUS"
        if critical:
            return "SUSPICIOUS"
        if any(f.severity == Severity.HIGH for f in high_confidence):
            return "SUSPICIOUS"
        if any(f.severity in (Severity.MEDIUM, Severity.LOW) for f in self.findings):
            return "WARNING"
        return "CLEAN"

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        priority = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for sev in priority:
            if any(f.severity == sev for f in self.findings):
                return sev
        return None
