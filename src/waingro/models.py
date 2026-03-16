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
class ParsedSkill:
    path: Path
    metadata: SkillMetadata
    body: str
    code_blocks: list[dict] = field(default_factory=list)
    bundled_files: list[Path] = field(default_factory=list)


@dataclass
class ScanResult:
    skill_path: Path
    metadata: SkillMetadata
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    rules_evaluated: int = 0

    @property
    def verdict(self) -> str:
        if any(f.severity == Severity.CRITICAL for f in self.findings):
            return "MALICIOUS"
        if any(f.severity == Severity.HIGH for f in self.findings):
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
