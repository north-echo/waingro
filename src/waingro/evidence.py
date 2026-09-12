"""Evidence types shared by static, ecosystem, and dynamic assessment.

The scanner deliberately separates *capability* from *intent*.  A shell, a
network client, or a package runner can be dangerous without being malicious.
These models make each evidence source and each missing source visible instead
of hiding that distinction in a single severity-derived label.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class EvidenceSource(StrEnum):
    STATIC = "static"
    BEHAVIOR_GRAPH = "behavior-graph"
    REGISTRY = "registry"
    ARTIFACT = "artifact"
    PROVENANCE = "provenance"
    REPUTATION = "reputation"
    RUNTIME = "runtime"
    EXTERNAL_INTELLIGENCE = "external-intelligence"


class EvidencePolarity(StrEnum):
    RISK = "risk"
    TRUST = "trust"
    CONTEXT = "context"


class AssessmentVerdict(StrEnum):
    CLEAN = "CLEAN"
    CAPABILITY = "CAPABILITY"
    REVIEW = "REVIEW"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


@dataclass(frozen=True)
class EvidenceItem:
    evidence_id: str
    source: EvidenceSource
    kind: str
    polarity: EvidencePolarity
    strength: float
    confidence: float
    summary: str
    details: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.strength <= 1.0:
            raise ValueError("evidence strength must be between 0 and 1")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("evidence confidence must be between 0 and 1")

    def to_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "source": self.source.value,
            "kind": self.kind,
            "polarity": self.polarity.value,
            "strength": round(self.strength, 3),
            "confidence": round(self.confidence, 3),
            "summary": self.summary,
            "details": self.details,
        }


@dataclass(frozen=True)
class EvidenceDimension:
    score: float
    confidence: float
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("dimension score must be between 0 and 1")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("dimension confidence must be between 0 and 1")

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 3),
            "confidence": round(self.confidence, 3),
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(frozen=True)
class AttackPath:
    stages: tuple[str, ...]
    confidence: float
    evidence_ids: tuple[str, ...]
    runtime_confirmed: bool = False

    def to_dict(self) -> dict:
        return {
            "stages": list(self.stages),
            "confidence": round(self.confidence, 3),
            "evidence_ids": list(self.evidence_ids),
            "runtime_confirmed": self.runtime_confirmed,
        }


@dataclass(frozen=True)
class HybridAssessment:
    verdict: AssessmentVerdict
    dimensions: dict[str, EvidenceDimension]
    evidence: tuple[EvidenceItem, ...]
    attack_paths: tuple[AttackPath, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    rationale: tuple[str, ...] = ()
    dynamic_recommended: bool = False
    dynamic_priority: str = "none"
    runtime_coverage: str = "not-run"
    schema_version: str = "2.1"

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "verdict": self.verdict.value,
            "dimensions": {
                name: dimension.to_dict()
                for name, dimension in sorted(self.dimensions.items())
            },
            "attack_paths": [path.to_dict() for path in self.attack_paths],
            "missing_evidence": list(self.missing_evidence),
            "dynamic_recommended": self.dynamic_recommended,
            "dynamic_priority": self.dynamic_priority,
            "runtime_coverage": self.runtime_coverage,
            "rationale": list(self.rationale),
            "evidence": [item.to_dict() for item in self.evidence],
        }
