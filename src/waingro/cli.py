"""WAINGRO CLI: Click-based command line interface."""

import json
import sys
from pathlib import Path

import click

from waingro import __version__
from waingro.analyzers.hybrid import assess_scan
from waingro.analyzers.risk_profile import compute_risk_profile
from waingro.dynamic.plan import build_dynamic_plan, preflight_hanna2, write_plan
from waingro.dynamic.runner import DynamicRunnerError, run_dynamic_job
from waingro.dynamic.trace import load_runtime_trace
from waingro.ecosystem import load_ecosystem_context
from waingro.evaluation import PREDICATES, evaluate_dataset
from waingro.models import Severity
from waingro.reporters.console import print_audit_results, print_result
from waingro.reporters.json_report import format_audit_json, format_json, result_to_dict
from waingro.resolvers.dependency_graph import resolve_dependency_graph
from waingro.resolvers.osv import OsvClient, query_vulnerabilities
from waingro.resolvers.package_artifact import (
    DEFAULT_MAX_ARTIFACT_BYTES,
    PackageArtifactClient,
    inspect_package_artifacts,
)
from waingro.resolvers.package_registry import (
    DEFAULT_MAX_METADATA_BYTES,
    RegistryMetadataClient,
    resolve_package_references,
)
from waingro.resolvers.provenance import SigstoreProvenanceVerifier
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
@click.option(
    "--expect-sha256",
    type=str,
    default=None,
    help="Require the scanned artifact scope to match this SHA-256 digest.",
)
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
    expect_sha256: str | None,
) -> None:
    """Scan an OpenClaw skill directory or SKILL.md file for security issues."""
    try:
        result = scan_skill(path)
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    if expect_sha256 is not None:
        expected = expect_sha256.lower()
        invalid_character = any(
            character not in "0123456789abcdef" for character in expected
        )
        if len(expected) != 64 or invalid_character:
            raise click.BadParameter(
                "must be exactly 64 hexadecimal characters",
                param_hint="--expect-sha256",
            )
        actual = result.artifact_identity.sha256 if result.artifact_identity else ""
        if actual != expected:
            raise click.ClickException(
                f"artifact SHA-256 mismatch: expected {expected}, scanned {actual}"
            )

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
@click.option(
    "--mode",
    type=click.Choice(["static", "hybrid-static"]),
    default="static",
    show_default=True,
    help="Evaluate legacy static verdicts or the evidence-separated hybrid model.",
)
@click.option("-f", "--format", "fmt", type=click.Choice(["console", "json"]), default="console")
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None)
@click.option("--fail-under-precision", type=click.FloatRange(0.0, 1.0), default=None)
@click.option("--fail-under-recall", type=click.FloatRange(0.0, 1.0), default=None)
def benchmark(
    dataset: Path,
    threshold: str,
    mode: str,
    fmt: str,
    output: Path | None,
    fail_under_precision: float | None,
    fail_under_recall: float | None,
) -> None:
    """Evaluate WAINGRO against DATASET/{benign,malicious} without executing it."""
    try:
        report = evaluate_dataset(dataset, analysis_mode=mode)
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    data = report.to_dict()
    selected = report.metrics(threshold)
    if fmt == "json":
        rendered = json.dumps(data, indent=2)
    else:
        lines = [
            f"Dataset: {data['dataset']}",
            f"Mode: {data['analysis_mode']}",
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


@main.command("resolve-packages")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--timeout", type=click.FloatRange(min=0.1), default=5.0, show_default=True)
@click.option(
    "--max-metadata-bytes",
    type=click.IntRange(min=1024),
    default=DEFAULT_MAX_METADATA_BYTES,
    show_default=True,
)
@click.option(
    "--inspect-artifacts",
    is_flag=True,
    default=False,
    help="Download and non-extractingly inspect resolved npm archives.",
)
@click.option(
    "--max-artifact-bytes",
    type=click.IntRange(min=1024),
    default=DEFAULT_MAX_ARTIFACT_BYTES,
    show_default=True,
)
@click.option(
    "--dependency-depth",
    type=click.IntRange(0, 5),
    default=0,
    show_default=True,
    help="Recursively inspect dependencies to this depth; requires artifact inspection.",
)
@click.option(
    "--max-dependency-nodes",
    type=click.IntRange(1, 2000),
    default=250,
    show_default=True,
)
@click.option(
    "--verify-provenance",
    is_flag=True,
    default=False,
    help="Cryptographically verify npm Sigstore provenance against repository identity.",
)
@click.option(
    "--offline-trust-root",
    is_flag=True,
    default=False,
    help="Use Sigstore's cached or bundled trust root without refreshing it.",
)
@click.option(
    "--osv",
    is_flag=True,
    default=False,
    help="Query OSV for exact resolved package versions.",
)
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None)
def resolve_packages(
    path: Path,
    timeout: float,
    max_metadata_bytes: int,
    inspect_artifacts: bool,
    max_artifact_bytes: int,
    dependency_depth: int,
    max_dependency_nodes: int,
    verify_provenance: bool,
    offline_trust_root: bool,
    osv: bool,
    output: Path | None,
) -> None:
    """Resolve runner references using official registry metadata without executing them."""
    if dependency_depth and not inspect_artifacts:
        raise click.UsageError("--dependency-depth requires --inspect-artifacts")
    try:
        result = scan_skill(path)
        client = RegistryMetadataClient(timeout=timeout, max_bytes=max_metadata_bytes)
        verifier = (
            SigstoreProvenanceVerifier(offline=offline_trust_root)
            if verify_provenance
            else None
        )
        resolutions = resolve_package_references(
            result.package_references,
            client,
            verifier,
        )
        inspections = []
        if inspect_artifacts:
            artifact_client = PackageArtifactClient(
                timeout=timeout,
                max_bytes=max_artifact_bytes,
            )
            inspections = inspect_package_artifacts(resolutions, artifact_client)
        dependency_graph = None
        if dependency_depth:
            dependency_graph = resolve_dependency_graph(
                resolutions,
                inspections,
                client,
                artifact_client,
                max_depth=dependency_depth,
                max_nodes=max_dependency_nodes,
                verify_provenance=verifier,
            )
        all_resolutions = [
            *resolutions,
            *(dependency_graph.resolutions if dependency_graph else []),
        ]
        vulnerabilities = (
            query_vulnerabilities(all_resolutions, OsvClient(timeout=timeout))
            if osv
            else []
        )
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    report = result_to_dict(result)
    report["package_resolutions"] = [resolution.to_dict() for resolution in resolutions]
    report["package_artifacts"] = [inspection.to_dict() for inspection in inspections]
    report["dependency_graph"] = (
        dependency_graph.to_dict() if dependency_graph else None
    )
    report["package_vulnerabilities"] = [item.to_dict() for item in vulnerabilities]
    rendered = json.dumps(report, indent=2)
    if output:
        output.write_text(rendered + "\n", encoding="utf-8")
    else:
        click.echo(rendered)


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--packages",
    is_flag=True,
    default=False,
    help="Resolve package references through official registry metadata APIs.",
)
@click.option(
    "--inspect-artifacts",
    is_flag=True,
    default=False,
    help="Download and non-extractingly inspect resolved npm archives.",
)
@click.option("--verify-provenance", is_flag=True, default=False)
@click.option("--offline-trust-root", is_flag=True, default=False)
@click.option("--osv", is_flag=True, default=False)
@click.option("--dependency-depth", type=click.IntRange(0, 5), default=0)
@click.option("--max-dependency-nodes", type=click.IntRange(1, 2000), default=250)
@click.option("--timeout", type=click.FloatRange(min=0.1), default=5.0, show_default=True)
@click.option(
    "--ecosystem-context",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option(
    "--runtime-trace",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option(
    "--runtime-signature",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option(
    "--allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option("--runtime-base-image-sha256", default=None)
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None)
def assess(
    path: Path,
    packages: bool,
    inspect_artifacts: bool,
    verify_provenance: bool,
    offline_trust_root: bool,
    osv: bool,
    dependency_depth: int,
    max_dependency_nodes: int,
    timeout: float,
    ecosystem_context: Path | None,
    runtime_trace: Path | None,
    runtime_signature: Path | None,
    allowed_signers: Path | None,
    runtime_base_image_sha256: str | None,
    output: Path | None,
) -> None:
    """Correlate static, ecosystem, package, provenance, and runtime evidence."""
    if inspect_artifacts and not packages:
        raise click.UsageError("--inspect-artifacts requires --packages")
    if verify_provenance and not packages:
        raise click.UsageError("--verify-provenance requires --packages")
    if osv and not packages:
        raise click.UsageError("--osv requires --packages")
    if dependency_depth and not inspect_artifacts:
        raise click.UsageError("--dependency-depth requires --inspect-artifacts")
    if bool(runtime_signature) != bool(allowed_signers):
        raise click.UsageError(
            "--runtime-signature and --allowed-signers must be supplied together"
        )
    if runtime_signature and not runtime_base_image_sha256:
        raise click.UsageError(
            "--runtime-base-image-sha256 is required for authenticated runtime evidence"
        )
    try:
        result = scan_skill(path)
        if result.artifact_identity is None:
            raise ValueError("scan did not produce an artifact identity")
        resolutions = []
        inspections = []
        dependency_graph = None
        vulnerabilities = []
        if packages:
            client = RegistryMetadataClient(timeout=timeout)
            verifier = (
                SigstoreProvenanceVerifier(offline=offline_trust_root)
                if verify_provenance
                else None
            )
            resolutions = resolve_package_references(
                result.package_references,
                client,
                verifier,
            )
            if inspect_artifacts:
                artifact_client = PackageArtifactClient(timeout=timeout)
                inspections = inspect_package_artifacts(resolutions, artifact_client)
                if dependency_depth:
                    dependency_graph = resolve_dependency_graph(
                        resolutions,
                        inspections,
                        client,
                        artifact_client,
                        max_depth=dependency_depth,
                        max_nodes=max_dependency_nodes,
                        verify_provenance=verifier,
                    )
            all_resolutions = [
                *resolutions,
                *(dependency_graph.resolutions if dependency_graph else []),
            ]
            if osv:
                vulnerabilities = query_vulnerabilities(
                    all_resolutions,
                    OsvClient(timeout=timeout),
                )
        context = (
            load_ecosystem_context(ecosystem_context, result.artifact_identity.sha256)
            if ecosystem_context
            else None
        )
        trace = (
            load_runtime_trace(
                runtime_trace,
                expected_artifact_sha256=result.artifact_identity.sha256,
                signature_path=runtime_signature,
                allowed_signers=allowed_signers,
                expected_base_image_sha256=runtime_base_image_sha256,
            )
            if runtime_trace
            else None
        )
        assessment = assess_scan(
            result,
            resolutions=[
                *resolutions,
                *(dependency_graph.resolutions if dependency_graph else []),
            ],
            inspections=[
                *inspections,
                *(dependency_graph.inspections if dependency_graph else []),
            ],
            vulnerabilities=vulnerabilities,
            ecosystem_context=context,
            runtime_trace=trace,
            dependency_graph=dependency_graph,
        )
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    report = result_to_dict(result)
    report["analysis_scope"] = "hybrid"
    report["static_verdict"] = report.pop("verdict")
    report["verdict"] = assessment.verdict.value
    report["assessment"] = assessment.to_dict()
    report["package_resolutions"] = [item.to_dict() for item in resolutions]
    report["package_artifacts"] = [item.to_dict() for item in inspections]
    report["dependency_graph"] = dependency_graph.to_dict() if dependency_graph else None
    report["package_vulnerabilities"] = [item.to_dict() for item in vulnerabilities]
    report["ecosystem_context"] = context.to_dict() if context else None
    report["runtime_trace"] = trace.to_dict() if trace else None
    rendered = json.dumps(report, indent=2)
    if output:
        output.write_text(rendered + "\n", encoding="utf-8")
    else:
        click.echo(rendered)


@main.group()
def dynamic() -> None:
    """Plan and validate KVM-isolated analysis on hanna2."""


@dynamic.command("preflight")
def dynamic_preflight() -> None:
    """Run read-only hanna2 KVM and libvirt readiness checks."""
    report = preflight_hanna2()
    click.echo(json.dumps(report, indent=2))
    if not report["ready"]:
        raise click.ClickException("host does not satisfy the hanna2 dynamic policy")


@dynamic.command("plan")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--base-image", required=True, help="Pinned base-image file name on hanna2.")
@click.option("--base-image-sha256", required=True)
@click.option(
    "--network-policy",
    type=click.Choice(["none"]),
    default="none",
    show_default=True,
)
@click.option("--timeout", "timeout_seconds", type=click.IntRange(10, 300), default=120)
@click.option("--memory", "memory_mib", type=click.IntRange(256, 2048), default=1024)
@click.option(
    "--authorize-execution",
    is_flag=True,
    default=False,
    help="Record explicit authorization in the plan; this command still starts no VM.",
)
@click.option("--interpreter", type=click.Choice(["python", "node", "shell"]), default=None)
@click.option("--entrypoint", default=None, help="Candidate-relative file at depth two or less.")
@click.option(
    "--argument",
    "arguments",
    multiple=True,
    help="Literal argument; never shell parsed.",
)
@click.option(
    "--require-executable",
    "required_executables",
    multiple=True,
    help="Guest executable required by the scenario; checked before VM boot.",
)
@click.option(
    "--synthetic-env",
    "synthetic_environment",
    multiple=True,
    metavar="NAME=PROFILE",
    help="Inject a named guest-only canary using a fixed value profile.",
)
@click.option(
    "--require-event",
    "required_event_types",
    multiple=True,
    type=click.Choice(
        ["credential", "defense-evasion", "dns", "file", "network", "persistence", "process"]
    ),
    help="Observable event required for complete scenario coverage.",
)
@click.option(
    "--require-exit-zero",
    is_flag=True,
    default=False,
    help="Require a zero candidate exit status for complete scenario coverage.",
)
@click.option("-o", "--output", type=click.Path(path_type=Path), required=True)
def dynamic_plan(
    path: Path,
    base_image: str,
    base_image_sha256: str,
    network_policy: str,
    timeout_seconds: int,
    memory_mib: int,
    authorize_execution: bool,
    interpreter: str | None,
    entrypoint: str | None,
    arguments: tuple[str, ...],
    required_executables: tuple[str, ...],
    synthetic_environment: tuple[str, ...],
    required_event_types: tuple[str, ...],
    require_exit_zero: bool,
    output: Path,
) -> None:
    """Create a non-overwriting, artifact-bound hanna2 execution plan."""
    try:
        result = scan_skill(path)
        if result.artifact_identity is None:
            raise ValueError("scan did not produce an artifact identity")
        parsed_environment = []
        for item in synthetic_environment:
            name, separator, profile = item.partition("=")
            if not separator:
                raise ValueError("--synthetic-env must use NAME=PROFILE")
            parsed_environment.append((name, profile))
        plan = build_dynamic_plan(
            result.artifact_identity,
            base_image=base_image,
            base_image_sha256=base_image_sha256,
            network_policy=network_policy,
            timeout_seconds=timeout_seconds,
            memory_mib=memory_mib,
            authorize_execution=authorize_execution,
            interpreter=interpreter,
            entrypoint=entrypoint,
            arguments=arguments,
            required_executables=required_executables,
            synthetic_environment=tuple(parsed_environment),
            required_event_types=required_event_types,
            require_exit_zero=require_exit_zero,
        )
        write_plan(plan, output)
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(plan.to_dict(), indent=2))


@dynamic.command("validate-trace")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.argument("trace", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--signature",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option(
    "--allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option("--base-image-sha256", default=None)
def dynamic_validate_trace(
    path: Path,
    trace: Path,
    signature: Path | None,
    allowed_signers: Path | None,
    base_image_sha256: str | None,
) -> None:
    """Validate and optionally authenticate a hanna2 runtime trace."""
    if bool(signature) != bool(allowed_signers):
        raise click.UsageError("--signature and --allowed-signers must be supplied together")
    if signature and not base_image_sha256:
        raise click.UsageError(
            "--base-image-sha256 is required for authenticated runtime evidence"
        )
    try:
        result = scan_skill(path)
        if result.artifact_identity is None:
            raise ValueError("scan did not produce an artifact identity")
        loaded = load_runtime_trace(
            trace,
            expected_artifact_sha256=result.artifact_identity.sha256,
            signature_path=signature,
            allowed_signers=allowed_signers,
            expected_base_image_sha256=base_image_sha256,
        )
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(loaded.to_dict(), indent=2))


@dynamic.command("run")
@click.argument(
    "plan",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.argument(
    "candidate",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option(
    "--confirm-job-id",
    required=True,
    help="Exact authorized job ID; prevents accidental execution of another plan.",
)
@click.option(
    "--image-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=Path("/var/lib/libvirt/images/waingro"),
    show_default=True,
)
@click.option(
    "--work-root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=Path("/var/lib/libvirt/images/waingro/jobs"),
    show_default=True,
)
@click.option(
    "--signing-key",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    required=True,
)
def dynamic_run(
    plan: Path,
    candidate: Path,
    confirm_job_id: str,
    image_dir: Path,
    work_root: Path,
    signing_key: Path | None,
    output: Path,
) -> None:
    """Run one explicitly authorized job; available only on hardened hanna2."""
    try:
        result = run_dynamic_job(
            plan,
            candidate,
            confirm_job_id=confirm_job_id,
            image_dir=image_dir,
            work_root=work_root,
            output_trace=output,
            signing_key=signing_key,
        )
    except (DynamicRunnerError, OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(result.to_dict(), indent=2))


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
