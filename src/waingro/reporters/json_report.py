"""Structured JSON output for scan results."""

import json
from pathlib import Path

from waingro import __version__
from waingro.models import ScanResult, Severity


def _at_or_above(severity: Severity, threshold: Severity) -> bool:
    return list(Severity).index(severity) <= list(Severity).index(threshold)


def _display_path(result: ScanResult, path: Path) -> str:
    if not path.is_absolute():
        return str(path)
    try:
        return str(path.relative_to(result.skill_path))
    except ValueError:
        return str(path)


def result_to_dict(result: ScanResult, min_severity: Severity = Severity.INFO) -> dict:
    """Convert a ScanResult to a JSON-serializable dict."""
    findings = [f for f in result.findings if _at_or_above(f.severity, min_severity)]
    counts = {sev: 0 for sev in Severity}
    for f in findings:
        counts[f.severity] += 1

    return {
        "version": __version__,
        "scan_path": str(result.skill_path),
        "metadata": {
            "name": result.metadata.name,
            "version": result.metadata.version,
            "author": result.metadata.author,
        },
        "artifact": (
            result.artifact_identity.to_dict() if result.artifact_identity else None
        ),
        "package_references": [
            {
                "runner": reference.runner,
                "selector": reference.selector,
                "file_path": _display_path(result, reference.file_path),
                "line_number": reference.line_number,
                "immutable": reference.immutable,
                "network_allowed": reference.network_allowed,
            }
            for reference in result.package_references
        ],
        "verdict": result.verdict,
        "security_tool_score": result.security_tool_score,
        "risk_profile": result.risk_profile,
        "files_scanned": result.files_scanned,
        "rules_evaluated": result.rules_evaluated,
        "summary": {
            "critical": counts[Severity.CRITICAL],
            "high": counts[Severity.HIGH],
            "medium": counts[Severity.MEDIUM],
            "low": counts[Severity.LOW],
            "info": counts[Severity.INFO],
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category.value,
                "file_path": _display_path(result, f.file_path),
                "line_number": f.line_number,
                "matched_content": f.matched_content,
                "remediation": f.remediation,
                "reference": f.reference,
                "confidence": f.confidence,
                "context_note": f.context_note,
            }
            for f in findings
        ],
    }


def format_json(result: ScanResult, min_severity: Severity = Severity.INFO) -> str:
    """Format a ScanResult as a JSON string."""
    return json.dumps(result_to_dict(result, min_severity), indent=2)


def format_audit_json(results: list[ScanResult]) -> str:
    """Format multiple ScanResults as a JSON string."""
    return json.dumps(
        {
            "version": __version__,
            "skills": [result_to_dict(r) for r in results],
        },
        indent=2,
    )


def write_json(result: ScanResult, output: Path) -> None:
    """Write JSON report to a file."""
    output.write_text(format_json(result))
