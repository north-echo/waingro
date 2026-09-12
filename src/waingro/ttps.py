"""Stable ATT&CK technique references for explainable evidence output."""

from __future__ import annotations

from waingro.models import Finding, FindingCategory

_CATEGORY_TECHNIQUES = {
    FindingCategory.EXECUTION: ("T1059",),
    FindingCategory.EXFILTRATION: ("T1041",),
    FindingCategory.PERSISTENCE: ("T1547",),
    FindingCategory.NETWORK: ("T1071",),
    FindingCategory.OBFUSCATION: ("T1027",),
    FindingCategory.INJECTION: ("T1055",),
    FindingCategory.SOCIAL_ENGINEERING: ("T1204",),
    FindingCategory.TYPOSQUATTING: ("T1195.002",),
    FindingCategory.BEHAVIORAL_MISMATCH: ("T1036",),
    FindingCategory.SUPPLY_CHAIN: ("T1195.002",),
    FindingCategory.SCOPE_ESCALATION: ("T1068",),
    FindingCategory.CROSS_TOOL: ("T1210",),
}

_RULE_TECHNIQUES = {
    "EXEC-001": ("T1105", "T1059"),
    "EXEC-002": ("T1027", "T1059"),
    "EXFIL-001": ("T1552.001",),
    "EXFIL-004": ("T1552.001",),
    "NET-001": ("T1059", "T1071"),
    "NET-002": ("T1071",),
    "NET-004": ("T1048",),
    "BEHAV-004": ("T1195.002", "T1105", "T1059"),
}

_RUNTIME_TECHNIQUES = {
    "execution": ("T1059",),
    "file-access": ("T1005",),
    "network": ("T1071",),
    "persistence": ("T1547",),
    "credential-access": ("T1552.001",),
    "evasion": ("T1027",),
}


def techniques_for_finding(finding: Finding) -> tuple[str, ...]:
    return _RULE_TECHNIQUES.get(
        finding.rule_id,
        _CATEGORY_TECHNIQUES.get(finding.category, ()),
    )


def techniques_for_runtime_stage(stage: str) -> tuple[str, ...]:
    return _RUNTIME_TECHNIQUES.get(stage, ())
