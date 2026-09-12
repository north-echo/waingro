"""Tests for semantic, ordered static attack-path construction."""

from pathlib import Path

from waingro.analyzers.behavior_graph import build_static_attack_paths
from waingro.evidence import EvidenceItem, EvidencePolarity, EvidenceSource
from waingro.models import Finding, FindingCategory, Severity


def _finding(rule: str, category: FindingCategory, line: int) -> Finding:
    return Finding(
        rule_id=rule,
        title=rule,
        description=rule,
        severity=Severity.HIGH,
        category=category,
        file_path=Path("script.py"),
        line_number=line,
        matched_content=rule,
        remediation="review",
        reference=None,
        confidence=0.9,
    )


def _evidence(findings: list[Finding]) -> dict[int, EvidenceItem]:
    return {
        id(finding): EvidenceItem(
            evidence_id=f"static:{finding.rule_id}:{index}",
            source=EvidenceSource.STATIC,
            kind=finding.category.value,
            polarity=EvidencePolarity.RISK,
            strength=0.5,
            confidence=finding.confidence,
            summary=finding.title,
        )
        for index, finding in enumerate(findings)
    }


def test_credential_references_and_exposure_do_not_manufacture_exfiltration():
    findings = [
        _finding("EXFIL-001", FindingCategory.EXFILTRATION, 10),
        _finding("EXFIL-006", FindingCategory.EXFILTRATION, 20),
    ]

    assert build_static_attack_paths(findings, _evidence(findings)) == []


def test_string_concatenation_and_mismatch_do_not_manufacture_execution_path():
    findings = [
        _finding("OBFUSC-002", FindingCategory.OBFUSCATION, 10),
        _finding("BEHAV-001", FindingCategory.BEHAVIORAL_MISMATCH, 20),
    ]

    assert build_static_attack_paths(findings, _evidence(findings)) == []


def test_composite_flow_rule_forms_a_path_without_unrelated_companion_finding():
    finding = _finding("EXFIL-008", FindingCategory.EXFILTRATION, 10)

    paths = build_static_attack_paths([finding], _evidence([finding]))

    assert len(paths) == 1
    assert paths[0].stages == ("data-access", "exfiltration")
    assert len(paths[0].evidence_ids) == 1


def test_paired_path_requires_source_before_sink():
    findings = [
        _finding("NET-006", FindingCategory.NETWORK, 10),
        _finding("EXFIL-005", FindingCategory.EXFILTRATION, 20),
    ]

    assert build_static_attack_paths(findings, _evidence(findings)) == []
