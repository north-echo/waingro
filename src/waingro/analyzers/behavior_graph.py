"""Build small, explainable attack paths from independent observations."""

from __future__ import annotations

from collections import defaultdict

from waingro.evidence import AttackPath, EvidenceItem
from waingro.models import Finding, FindingCategory

_CATEGORY_STAGE = {
    FindingCategory.EXECUTION: "execution",
    FindingCategory.EXFILTRATION: "exfiltration",
    FindingCategory.PERSISTENCE: "persistence",
    FindingCategory.NETWORK: "network",
    FindingCategory.OBFUSCATION: "evasion",
    FindingCategory.INJECTION: "injection",
    FindingCategory.SOCIAL_ENGINEERING: "initial-access",
    FindingCategory.TYPOSQUATTING: "initial-access",
    FindingCategory.BEHAVIORAL_MISMATCH: "execution",
    FindingCategory.SUPPLY_CHAIN: "supply-chain",
    FindingCategory.SCOPE_ESCALATION: "privilege-escalation",
    FindingCategory.CROSS_TOOL: "lateral-movement",
}

_RULE_STAGE = {
    "EXFIL-001": "credential-access",
    "EXFIL-004": "credential-access",
    "NET-002": "command-and-control",
    "NET-004": "exfiltration",
}

_PATHS = (
    ("credential-access", "exfiltration"),
    ("credential-access", "network"),
    ("credential-access", "command-and-control"),
    ("evasion", "execution"),
    ("initial-access", "execution"),
    ("supply-chain", "execution"),
    ("execution", "persistence"),
    ("execution", "command-and-control"),
    ("injection", "execution"),
)


def finding_stage(finding: Finding) -> str:
    return _RULE_STAGE.get(finding.rule_id, _CATEGORY_STAGE[finding.category])


def build_static_attack_paths(
    findings: list[Finding], evidence_by_finding: dict[int, EvidenceItem]
) -> list[AttackPath]:
    """Correlate stages only when findings share a file.

    Same-file correlation avoids manufacturing an attack chain from unrelated
    examples spread through a documentation or security-signature corpus.
    """
    by_file: dict[str, dict[str, list[tuple[Finding, EvidenceItem]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for finding in findings:
        item = evidence_by_finding.get(id(finding))
        if item is None or finding.confidence < 0.5:
            continue
        by_file[str(finding.file_path)][finding_stage(finding)].append((finding, item))

    paths: list[AttackPath] = []
    seen: set[tuple[str, str, str]] = set()
    for file_path, stages in by_file.items():
        for source, sink in _PATHS:
            if source not in stages or sink not in stages:
                continue
            key = (file_path, source, sink)
            if key in seen:
                continue
            seen.add(key)
            left = max(stages[source], key=lambda pair: pair[0].confidence)
            right = max(stages[sink], key=lambda pair: pair[0].confidence)
            confidence = min(left[0].confidence, right[0].confidence)
            paths.append(
                AttackPath(
                    stages=(source, sink),
                    confidence=confidence,
                    evidence_ids=(left[1].evidence_id, right[1].evidence_id),
                )
            )
    return paths
