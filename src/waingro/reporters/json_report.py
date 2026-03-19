"""Structured JSON output for scan results."""

import json
from pathlib import Path

from waingro import __version__
from waingro.models import ScanResult, Severity


def result_to_dict(result: ScanResult) -> dict:
    """Convert a ScanResult to a JSON-serializable dict."""
    counts = {sev: 0 for sev in Severity}
    for f in result.findings:
        counts[f.severity] += 1

    return {
        "version": __version__,
        "scan_path": str(result.skill_path),
        "verdict": result.verdict,
        "security_tool_score": result.security_tool_score,
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
                "file_path": f.file_path.name,
                "line_number": f.line_number,
                "matched_content": f.matched_content,
                "remediation": f.remediation,
                "reference": f.reference,
                "confidence": f.confidence,
                "context_note": f.context_note,
            }
            for f in result.findings
        ],
    }


def format_json(result: ScanResult) -> str:
    """Format a ScanResult as a JSON string."""
    return json.dumps(result_to_dict(result), indent=2)


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
