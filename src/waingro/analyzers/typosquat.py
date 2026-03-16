"""Typosquat detection: Levenshtein distance against known-good skill names."""

from pathlib import Path

from waingro.models import Finding, FindingCategory, Severity


def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost))
        prev = curr
    return prev[len(b)]


def load_known_good_skills(path: Path) -> list[str]:
    """Load known-good skill names from a text file (one per line)."""
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def check_typosquat(
    skill_name: str, known_good: list[str], threshold: int = 2
) -> list[Finding]:
    """Check if a skill name is suspiciously close to a known-good name."""
    findings = []
    skill_lower = skill_name.lower()

    for good_name in known_good:
        good_lower = good_name.lower()
        if skill_lower == good_lower:
            continue
        dist = _levenshtein(skill_lower, good_lower)
        if 0 < dist <= threshold:
            findings.append(Finding(
                rule_id="TYPO-001",
                title="Potential typosquat",
                description=(
                    f'Skill name "{skill_name}" is similar to known skill '
                    f'"{good_name}" (distance: {dist})'
                ),
                severity=Severity.HIGH,
                category=FindingCategory.TYPOSQUATTING,
                file_path=Path("SKILL.md"),
                line_number=None,
                matched_content=f"{skill_name} ~= {good_name}",
                remediation=f'Verify this is not a typosquat of "{good_name}".',
                reference=None,
            ))
    return findings
