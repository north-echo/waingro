"""WAINGRO CLI: Click-based command line interface."""

import sys
from pathlib import Path

import click

from waingro import __version__
from waingro.models import Severity
from waingro.reporters.console import print_audit_results, print_result
from waingro.reporters.json_report import format_audit_json, format_json
from waingro.scanner import audit_skills, scan_skill

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
    "-s", "--severity", "min_severity",
    type=click.Choice(list(SEVERITY_MAP.keys())), default="low",
)
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), default=None)
@click.option("--no-color", is_flag=True, default=False)
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None)
@click.option("-q", "--quiet", is_flag=True, default=False)
@click.option("-v", "--verbose", is_flag=True, default=False)
def scan(
    path: Path,
    fmt: str,
    min_severity: str,
    fail_on: str | None,
    no_color: bool,
    output: Path | None,
    quiet: bool,
    verbose: bool,
) -> None:
    """Scan an OpenClaw skill directory or SKILL.md file for security issues."""
    result = scan_skill(path)

    # Filter by minimum severity
    min_sev = SEVERITY_MAP[min_severity]
    result.findings = [f for f in result.findings if _severity_at_or_above(f.severity, min_sev)]

    if fmt == "json":
        text = format_json(result)
        if output:
            output.write_text(text)
        else:
            click.echo(text)
    else:
        if output:
            print_result(result, quiet=quiet, no_color=True)
        else:
            print_result(result, quiet=quiet, no_color=no_color)

    # Exit code
    if fail_on:
        fail_sev = SEVERITY_MAP[fail_on]
        if any(_severity_at_or_above(f.severity, fail_sev) for f in result.findings):
            sys.exit(1)


@main.command()
@click.argument("skills_dir", type=click.Path(exists=True, path_type=Path))
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
            output.write_text(text)
        else:
            click.echo(text)
    else:
        print_audit_results(results, quiet=quiet, no_color=no_color)

    if fail_on:
        fail_sev = SEVERITY_MAP[fail_on]
        for r in results:
            if any(_severity_at_or_above(f.severity, fail_sev) for f in r.findings):
                sys.exit(1)


@main.command()
def version() -> None:
    """Print version information."""
    click.echo(f"waingro {__version__}")
