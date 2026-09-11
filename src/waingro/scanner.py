"""Scanner orchestrator: parse -> analyze -> produce ScanResult."""

import hashlib
from pathlib import Path

from waingro.analyzers.aggregate import (
    aggregate_by_file_spread,
    aggregate_findings,
    suppress_redundant,
)
from waingro.analyzers.artifact import build_artifact_identity
from waingro.analyzers.context import (
    adjust_finding_confidence,
    annotate_security_tool_name,
    compute_security_tool_score,
)
from waingro.analyzers.package_runner import find_package_runners
from waingro.analyzers.risk_profile import compute_risk_profile
from waingro.analyzers.static import run_static_analysis
from waingro.analyzers.typosquat import check_typosquat, load_known_good_skills
from waingro.models import BundledFileContent, PackageReference, ParsedSkill, ScanResult
from waingro.parsers.script import read_file_bytes
from waingro.parsers.skill import parse_skill

DEFAULT_KNOWN_GOOD = (
    Path(__file__).parent / "data" / "known_skills.txt"
)


def load_skill(path: Path) -> ParsedSkill:
    """Parse a skill and load the contents of its bundled files."""
    skill = parse_skill(path)
    for bf in skill.bundled_files:
        raw_content = read_file_bytes(bf)
        skill.bundled_content.append(
            BundledFileContent(
                path=bf,
                content=raw_content.decode("utf-8", errors="replace"),
                sha256=hashlib.sha256(raw_content).hexdigest(),
                size_bytes=len(raw_content),
            )
        )
    return skill


def scan_skill(path: Path, known_good_path: Path | None = None) -> ScanResult:
    """Scan a single skill directory or SKILL.md file."""
    skill = load_skill(path)
    artifact_identity = build_artifact_identity(skill)
    package_references = [
        PackageReference(
            runner=invocation.runner,
            selector=invocation.package,
            file_path=invocation.file_path,
            line_number=invocation.line_number,
            immutable=invocation.immutable,
            network_allowed=invocation.network_allowed,
        )
        for invocation in find_package_runners(skill)
    ]

    # Static analysis
    findings, rules_evaluated = run_static_analysis(skill)

    # Typosquat check
    kg_path = known_good_path or DEFAULT_KNOWN_GOOD
    known_good = load_known_good_skills(kg_path)
    if known_good:
        typo_findings = check_typosquat(skill.metadata.name, known_good)
        findings.extend(typo_findings)

    # Context analysis — adjust confidence for security tools
    security_tool_score = compute_security_tool_score(skill, findings)
    findings = adjust_finding_confidence(findings, security_tool_score, skill)
    findings = annotate_security_tool_name(findings, skill)

    # Collapse repeats so one property counts once: per (rule, file), then
    # across files, dropping what a more precise rule already covers.
    findings = aggregate_findings(findings)
    findings = suppress_redundant(findings)
    findings = aggregate_by_file_spread(findings)

    # Risk profile
    profile = compute_risk_profile(findings, security_tool_score)

    return ScanResult(
        skill_path=skill.path,
        metadata=skill.metadata,
        findings=findings,
        files_scanned=1 + len(skill.bundled_content),
        rules_evaluated=rules_evaluated,
        security_tool_score=security_tool_score,
        risk_profile=profile.to_dict(),
        artifact_identity=artifact_identity,
        package_references=package_references,
    )


def audit_skills(directory: Path, known_good_path: Path | None = None) -> list[ScanResult]:
    """Scan all skill directories under a parent directory."""
    results = []
    if not directory.is_dir():
        return results

    for child in sorted(directory.iterdir()):
        if child.is_dir() and (child / "SKILL.md").exists():
            results.append(scan_skill(child, known_good_path))

    return results
