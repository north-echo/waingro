"""Scanner orchestrator: parse -> analyze -> produce ScanResult."""

from pathlib import Path

from waingro.analyzers.static import run_static_analysis
from waingro.analyzers.typosquat import check_typosquat, load_known_good_skills
from waingro.models import ScanResult
from waingro.parsers.script import read_script
from waingro.parsers.skill import parse_skill

DEFAULT_KNOWN_GOOD = (
    Path(__file__).parent.parent.parent / "tests" / "fixtures" / "known_good_skills.txt"
)


def scan_skill(path: Path, known_good_path: Path | None = None) -> ScanResult:
    """Scan a single skill directory or SKILL.md file."""
    skill = parse_skill(path)

    # Count files scanned
    files_scanned = 1  # SKILL.md
    for bf in skill.bundled_files:
        _ = read_script(bf)
        files_scanned += 1

    # Static analysis
    findings, rules_evaluated = run_static_analysis(skill)

    # Typosquat check
    kg_path = known_good_path or DEFAULT_KNOWN_GOOD
    known_good = load_known_good_skills(kg_path)
    if known_good:
        typo_findings = check_typosquat(skill.metadata.name, known_good)
        findings.extend(typo_findings)

    return ScanResult(
        skill_path=skill.path,
        metadata=skill.metadata,
        findings=findings,
        files_scanned=files_scanned,
        rules_evaluated=rules_evaluated,
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
