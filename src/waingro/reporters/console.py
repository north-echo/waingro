"""Rich-formatted console output."""

from rich.console import Console

from waingro import __version__
from waingro.models import ScanResult, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

VERDICT_COLORS = {
    "MALICIOUS": "bold red",
    "SUSPICIOUS": "red",
    "WARNING": "yellow",
    "CLEAN": "bold green",
}


def print_result(result: ScanResult, quiet: bool = False, no_color: bool = False) -> None:
    """Print scan result to console with Rich formatting."""
    console = Console(no_color=no_color)

    if not quiet:
        console.print()
        console.print(f" WAINGRO v{__version__} -- AI Agent Skill Security Scanner", style="bold")
        console.print()
        console.print(f" Scanning: {result.skill_path}")
        console.print(f" Files scanned: {result.files_scanned}")
        console.print(f" Rules evaluated: {result.rules_evaluated}")
        console.print()

    verdict_style = VERDICT_COLORS.get(result.verdict, "bold")
    console.print(f" VERDICT: {result.verdict}", style=verdict_style)

    if quiet:
        return

    if result.findings:
        console.print()

    for finding in result.findings:
        sev_style = SEVERITY_COLORS.get(finding.severity, "")
        sev_label = finding.severity.value.upper().ljust(9)

        console.print(f" {sev_label} {finding.rule_id}  {finding.title}", style=sev_style)

        file_name = finding.file_path.name
        if finding.line_number:
            console.print(f"           File: {file_name}, Line: {finding.line_number}")
        else:
            console.print(f"           File: {file_name}")

        console.print(f"           Match: {finding.matched_content}")
        console.print(f"           Remediation: {finding.remediation}")

        if finding.reference:
            console.print(f"           Ref: {finding.reference}")

        console.print()

    # Summary
    if result.findings:
        counts = {sev: 0 for sev in Severity}
        for f in result.findings:
            counts[f.severity] += 1
        parts = [
            f"{counts[Severity.CRITICAL]} CRITICAL",
            f"{counts[Severity.HIGH]} HIGH",
            f"{counts[Severity.MEDIUM]} MEDIUM",
            f"{counts[Severity.LOW]} LOW",
        ]
        console.print(f" Summary: {', '.join(parts)}")
        console.print()


def print_audit_results(
    results: list[ScanResult], quiet: bool = False, no_color: bool = False
) -> None:
    """Print audit results for multiple skills."""
    console = Console(no_color=no_color)

    if not quiet:
        console.print()
        console.print(f" WAINGRO v{__version__} -- AI Agent Skill Security Scanner", style="bold")
        console.print(f" Auditing {len(results)} skills")
        console.print()

    for result in results:
        verdict_style = VERDICT_COLORS.get(result.verdict, "bold")
        finding_count = len(result.findings)
        console.print(
            f" [{result.verdict}]  {result.metadata.name}  ({finding_count} findings)",
            style=verdict_style,
        )

    console.print()

    # Overall summary
    total_findings = sum(len(r.findings) for r in results)
    malicious = sum(1 for r in results if r.verdict == "MALICIOUS")
    suspicious = sum(1 for r in results if r.verdict == "SUSPICIOUS")
    clean = sum(1 for r in results if r.verdict == "CLEAN")
    console.print(f" Total: {len(results)} skills, {total_findings} findings")
    console.print(f" {malicious} malicious, {suspicious} suspicious, {clean} clean")
    console.print()
