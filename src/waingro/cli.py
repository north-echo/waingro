"""WAINGRO CLI: Click-based command line interface."""

import json
import sys
from pathlib import Path

import click

from waingro import __version__
from waingro.analyzers.risk_profile import compute_risk_profile
from waingro.evaluation import PREDICATES, evaluate_dataset
from waingro.models import Severity
from waingro.reporters.console import print_audit_results, print_result
from waingro.reporters.json_report import format_audit_json, format_json
from waingro.scanner import audit_skills, load_skill, scan_skill

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _severity_at_or_above(severity: Severity, threshold: Severity) -> bool:
    return SEVERITY_ORDER.index(severity) <= SEVERITY_ORDER.index(threshold)


@click.group()
@click.version_option(__version__, prog_name="waingro")
def main() -> None:
    """WAINGRO: AI Agent Skill Security Scanner."""


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("-f", "--format", "fmt", type=click.Choice(["console", "json"]), default="console")
@click.option(
    "-s",
    "--severity",
    "min_severity",
    type=click.Choice(list(SEVERITY_MAP.keys())),
    default="low",
)
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), default=None)
@click.option("--no-color", is_flag=True, default=False)
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None)
@click.option("-q", "--quiet", is_flag=True, default=False)
@click.option("-v", "--verbose", is_flag=True, default=False)
@click.option("--semantic", is_flag=True, default=False, help="Enable Claude API semantic analysis")
@click.option("--semantic-budget", type=float, default=5.0, help="Max spend for semantic analysis")
def scan(
    path: Path,
    fmt: str,
    min_severity: str,
    fail_on: str | None,
    no_color: bool,
    output: Path | None,
    quiet: bool,
    verbose: bool,
    semantic: bool,
    semantic_budget: float,
) -> None:
    """Scan an OpenClaw skill directory or SKILL.md file for security issues."""
    try:
        result = scan_skill(path)
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    if semantic and result.findings:
        from waingro.analyzers.semantic import SemanticAnalyzer

        analyzer = SemanticAnalyzer(budget=semantic_budget)
        if analyzer.should_analyze(result.verdict, result.security_tool_score):
            skill = load_skill(path)
            api_result = analyzer.analyze(skill, result.findings)
            result.findings = analyzer.apply_results(result.findings, api_result)
            result.risk_profile = compute_risk_profile(
                result.findings,
                result.security_tool_score,
            ).to_dict()

    min_sev = SEVERITY_MAP[min_severity]

    if fmt == "json":
        text = format_json(result, min_sev)
        if output:
            output.write_text(text, encoding="utf-8")
        else:
            click.echo(text)
    else:
        if output:
            with output.open("w", encoding="utf-8") as handle:
                print_result(
                    result,
                    quiet=quiet,
                    no_color=True,
                    file=handle,
                    min_severity=min_sev,
                )
        else:
            print_result(
                result,
                quiet=quiet,
                no_color=no_color,
                min_severity=min_sev,
            )

    # Exit code
    if fail_on:
        fail_sev = SEVERITY_MAP[fail_on]
        if any(_severity_at_or_above(f.severity, fail_sev) for f in result.findings):
            sys.exit(1)


@main.command()
@click.argument(
    "skills_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option("-f", "--format", "fmt", type=click.Choice(["console", "json"]), default="console")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), default=None)
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None)
@click.option("-q", "--quiet", is_flag=True, default=False)
@click.option("--no-color", is_flag=True, default=False)
def audit(
    skills_dir: Path,
    fmt: str,
    fail_on: str | None,
    output: Path | None,
    quiet: bool,
    no_color: bool,
) -> None:
    """Audit all installed skills in a directory."""
    results = audit_skills(skills_dir)

    if fmt == "json":
        text = format_audit_json(results)
        if output:
            output.write_text(text, encoding="utf-8")
        else:
            click.echo(text)
    else:
        if output:
            with output.open("w", encoding="utf-8") as handle:
                print_audit_results(results, quiet=quiet, no_color=True, file=handle)
        else:
            print_audit_results(results, quiet=quiet, no_color=no_color)

    if fail_on:
        fail_sev = SEVERITY_MAP[fail_on]
        for r in results:
            if any(_severity_at_or_above(f.severity, fail_sev) for f in r.findings):
                sys.exit(1)


@main.command()
@click.argument(
    "dataset",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option(
    "--threshold",
    type=click.Choice(list(PREDICATES)),
    default="suspicious",
    show_default=True,
    help="Verdict boundary used for pass/fail metrics.",
)
@click.option("-f", "--format", "fmt", type=click.Choice(["console", "json"]), default="console")
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None)
@click.option("--fail-under-precision", type=click.FloatRange(0.0, 1.0), default=None)
@click.option("--fail-under-recall", type=click.FloatRange(0.0, 1.0), default=None)
def benchmark(
    dataset: Path,
    threshold: str,
    fmt: str,
    output: Path | None,
    fail_under_precision: float | None,
    fail_under_recall: float | None,
) -> None:
    """Evaluate WAINGRO against DATASET/{benign,malicious} without executing it."""
    try:
        report = evaluate_dataset(dataset)
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    data = report.to_dict()
    selected = report.metrics(threshold)
    if fmt == "json":
        rendered = json.dumps(data, indent=2)
    else:
        lines = [
            f"Dataset: {data['dataset']}",
            f"Cases: {data['cases']}  Errors: {len(data['errors'])}",
            "",
            "Threshold       Precision  Recall  Specificity  F1       TP  FP  TN  FN",
        ]
        for name in PREDICATES:
            metrics = report.metrics(name)
            lines.append(
                f"{name:15s} {metrics.precision:9.1%} {metrics.recall:7.1%} "
                f"{metrics.specificity:11.1%} {metrics.f1:7.1%} "
                f"{metrics.true_positive:3d} {metrics.false_positive:3d} "
                f"{metrics.true_negative:3d} {metrics.false_negative:3d}"
            )
        lines.extend(("", "Malicious-category recall at SUSPICIOUS+:"))
        for category, values in data["malicious_category_recall_at_suspicious"].items():
            lines.append(
                f"  {category:32s} {values['detected']:3d}/{values['total']:<3d} "
                f"({values['recall']:.1%})"
            )
        rendered = "\n".join(lines)

    if output:
        output.write_text(rendered + "\n", encoding="utf-8")
    else:
        click.echo(rendered)

    if report.errors:
        raise click.ClickException(f"benchmark completed with {len(report.errors)} scan errors")
    if fail_under_precision is not None and selected.precision < fail_under_precision:
        raise click.ClickException(
            f"precision {selected.precision:.4f} is below {fail_under_precision:.4f}"
        )
    if fail_under_recall is not None and selected.recall < fail_under_recall:
        raise click.ClickException(
            f"recall {selected.recall:.4f} is below {fail_under_recall:.4f}"
        )


@main.command()
def version() -> None:
    """Print version information."""
    click.echo(f"waingro {__version__}")


# ── MCP subcommand group ──────────────────────────────────────────────


@main.group()
def mcp() -> None:
    """MCP server ecosystem scanner."""


@mcp.command("scan")
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("-f", "--format", "fmt", type=click.Choice(["console", "json"]), default="console")
@click.option(
    "-s",
    "--severity",
    "min_severity",
    type=click.Choice(list(SEVERITY_MAP.keys())),
    default="low",
)
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), default=None)
def mcp_scan(path: Path, fmt: str, min_severity: str, fail_on: str | None) -> None:
    """Scan an MCP server directory for security issues."""
    from waingro.mcp.scanner import scan_server as mcp_scan_server

    try:
        result = mcp_scan_server(path)
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    min_sev = SEVERITY_MAP[min_severity]
    visible_findings = [f for f in result.findings if _severity_at_or_above(f.severity, min_sev)]

    if fmt == "json":
        import json as _json

        output = {
            "server": str(result.server_path),
            "name": result.metadata.name,
            "version": result.metadata.version,
            "verdict": result.verdict,
            "files_scanned": result.files_scanned,
            "rules_evaluated": result.rules_evaluated,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "category": f.category.value,
                    "file": str(f.file_path),
                    "line": f.line_number,
                    "matched": f.matched_content,
                    "confidence": f.confidence,
                }
                for f in visible_findings
            ],
        }
        click.echo(_json.dumps(output, indent=2))
    else:
        color = {
            "MALICIOUS": "red",
            "SUSPICIOUS": "yellow",
            "WARNING": "yellow",
            "REVIEW": "blue",
            "CLEAN": "green",
        }.get(result.verdict, "white")
        click.echo(f"\n{'=' * 60}")
        click.echo(f"{result.metadata.name} ({result.metadata.version or 'unknown'})")
        click.echo(f"  Verdict: {click.style(result.verdict, fg=color)}")
        click.echo(f"  Files:   {result.files_scanned}")
        click.echo(f"  Tools:   {len(result.metadata.tools)}")
        if visible_findings:
            click.echo(f"  Findings ({len(visible_findings)}):")
            sev_order = ["critical", "high", "medium", "low", "info"]
            for f in sorted(visible_findings, key=lambda x: sev_order.index(x.severity.value)):
                conf = f" (conf={f.confidence:.1f})" if f.confidence < 1.0 else ""
                click.echo(f"    [{f.severity.value.upper():8s}] {f.rule_id}: {f.title}{conf}")
                click.echo(f"             {f.matched_content[:80]}")
        click.echo()

    if fail_on:
        fail_sev = SEVERITY_MAP[fail_on]
        if any(_severity_at_or_above(f.severity, fail_sev) for f in result.findings):
            sys.exit(1)


@mcp.command("batch")
@click.argument("manifest", type=click.Path(exists=True, path_type=Path))
@click.option("--clone-dir", type=click.Path(path_type=Path), default=Path("cloned-servers"))
@click.option("--results", type=click.Path(path_type=Path), default=Path("batch-results.json"))
@click.option("--max", "max_servers", type=int, default=0, help="Max servers to scan (0=all)")
@click.option("--min-stars", type=int, default=0)
@click.option("--cleanup", is_flag=True, help="Delete repos after scanning")
def mcp_batch(
    manifest: Path,
    clone_dir: Path,
    results: Path,
    max_servers: int,
    min_stars: int,
    cleanup: bool,
) -> None:
    """Batch clone + scan MCP servers from a discovery manifest."""
    from waingro.mcp.batch import BatchConfig, run_batch_scan

    config = BatchConfig(
        manifest_path=manifest,
        clone_dir=clone_dir,
        results_path=results,
        max_servers=max_servers,
        min_stars=min_stars,
        cleanup_after_scan=cleanup,
    )
    result = run_batch_scan(config)

    if result.verdict_counts.get("MALICIOUS", 0) > 0:
        sys.exit(2)
    elif result.verdict_counts.get("SUSPICIOUS", 0) > 0:
        sys.exit(1)


@mcp.command("discover")
@click.option(
    "--awesome",
    type=click.Path(exists=True, path_type=Path),
    help="awesome-mcp-servers README.md",
)
@click.option("--no-npm", is_flag=True)
@click.option("--no-github", is_flag=True)
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    default=Path("discovery-manifest.json"),
)
def mcp_discover(awesome: Path | None, no_npm: bool, no_github: bool, output: Path) -> None:
    """Discover MCP servers from npm, GitHub, and awesome lists."""
    from waingro.mcp.discovery import run_discovery

    run_discovery(
        awesome_readme=awesome,
        include_npm=not no_npm,
        include_github=not no_github,
        output_path=output,
    )
