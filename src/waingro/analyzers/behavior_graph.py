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
    "BEHAV-001": "behavioral-mismatch",
    "BEHAV-002": "behavioral-mismatch",
    "EXFIL-001": "credential-reference",
    "EXFIL-002": "credential-access",
    "EXFIL-003": "credential-access",
    "EXFIL-004": "workspace-access",
    "EXFIL-005": "credential-access",
    "EXFIL-006": "credential-exposure",
    "EXFIL-007": "collection",
    "EXFIL-008": "exfiltration",
    "EXFIL-009": "exfiltration",
    "EXFIL-010": "credential-access",
    "NET-002": "command-and-control",
    "NET-004": "exfiltration",
    "NET-005": "exfiltration",
    "NET-007": "exfiltration",
    "OBFUSC-001": "encoded-content",
    "OBFUSC-002": "string-concatenation",
}

_COMPOSITE_RULE_PATHS = {
    "BEHAV-003": ("data-access", "exfiltration"),
    "BEHAV-004": ("supply-chain", "execution"),
    "EXEC-002": ("evasion", "execution"),
    "EXEC-005": ("evasion", "execution"),
    "EXEC-008": ("initial-access", "execution"),
    "EXEC-009": ("initial-access", "execution"),
    "EXFIL-008": ("data-access", "exfiltration"),
    "EXFIL-009": ("credential-access", "exfiltration"),
    "NET-004": ("data-access", "exfiltration"),
    "NET-005": ("credential-access", "exfiltration"),
    "NET-007": ("discovery", "exfiltration"),
    "SOCIAL-003": ("supply-chain", "execution"),
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
    for finding in findings:
        item = evidence_by_finding.get(id(finding))
        stages = _COMPOSITE_RULE_PATHS.get(finding.rule_id)
        if item is None or stages is None or finding.confidence < 0.5:
            continue
        file_path = str(finding.file_path)
        key = (file_path, *stages)
        if key in seen:
            continue
        seen.add(key)
        paths.append(
            AttackPath(
                stages=stages,
                confidence=finding.confidence,
                evidence_ids=(item.evidence_id,),
            )
        )
    for file_path, stages in by_file.items():
        for source, sink in _PATHS:
            if source not in stages or sink not in stages:
                continue
            key = (file_path, source, sink)
            if key in seen:
                continue
            ordered_pairs = [
                (left, right)
                for left in stages[source]
                for right in stages[sink]
                if (
                    left[0].line_number is None
                    or right[0].line_number is None
                    or left[0].line_number <= right[0].line_number
                )
            ]
            if not ordered_pairs:
                continue
            seen.add(key)
            left, right = max(
                ordered_pairs,
                key=lambda pair: min(pair[0][0].confidence, pair[1][0].confidence),
            )
            confidence = min(left[0].confidence, right[0].confidence)
            paths.append(
                AttackPath(
                    stages=(source, sink),
                    confidence=confidence,
                    evidence_ids=(left[1].evidence_id, right[1].evidence_id),
                )
            )
    return paths
