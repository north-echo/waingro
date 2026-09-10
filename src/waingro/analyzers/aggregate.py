"""Collapse repeated hits of one rule in one file into a single finding.

A rule that matches 101 times in one bundled file has found one property of
that file, not 101 problems. Reporting each hit separately inflates finding
counts, drowns the rest of the report, and pushes large repositories toward a
MALICIOUS verdict on volume alone. The March 2026 ClawHub audit and the MCP
ecosystem scan both recorded this as their dominant counting artifact.

Aggregation is presentational: nothing is discarded. The collapsed finding
keeps the highest severity and confidence seen in the group and records how
many occurrences it stands for and where the first few were.
"""

from collections import defaultdict

from waingro.models import Finding, Severity

# Fewer repeats than this stay as individual findings — a handful of distinct
# call sites is still useful detail for a reviewer.
COLLAPSE_THRESHOLD = 3

# How many example line numbers to name in the collapsed finding.
EXAMPLE_LINES = 5

# When one rule fires across at least this many distinct files in a single
# skill, it describes a property of the whole bundle rather than of any one
# file, and collapses again into a single skill-level finding.
FILE_SPREAD_THRESHOLD = 4

# How many example file names to name in a skill-level collapsed finding.
EXAMPLE_FILES = 4

# Rules whose per-line output is redundant once another rule has already
# reported the same file. Machine-obfuscated bundles are wall-to-wall hex
# escapes next to wall-to-wall eval/Function calls; OBFUSC-003 says that once,
# accurately, per file.
_REDUNDANT_IN_FILE = {
    "EXEC-005": "OBFUSC-003",
}

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def _worst(severities: list[Severity]) -> Severity:
    for sev in _SEVERITY_ORDER:
        if sev in severities:
            return sev
    return Severity.INFO


def aggregate_findings(
    findings: list[Finding], threshold: int = COLLAPSE_THRESHOLD,
) -> list[Finding]:
    """Collapse per-(rule, file) repeats, preserving first-seen order."""
    groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        groups[(f.rule_id, str(f.file_path))].append(f)

    out: list[Finding] = []
    emitted: set[tuple[str, str]] = set()
    for f in findings:
        key = (f.rule_id, str(f.file_path))
        group = groups[key]
        if len(group) < threshold:
            out.append(f)
            continue
        if key in emitted:
            continue
        emitted.add(key)

        lines = [g.line_number for g in group if g.line_number is not None]
        shown = ", ".join(str(n) for n in lines[:EXAMPLE_LINES])
        if len(lines) > EXAMPLE_LINES:
            shown += f", … (+{len(lines) - EXAMPLE_LINES} more)"
        first = group[0]

        out.append(Finding(
            rule_id=first.rule_id,
            title=first.title,
            description=first.description,
            severity=_worst([g.severity for g in group]),
            category=first.category,
            file_path=first.file_path,
            line_number=first.line_number,
            matched_content=f"{len(group)} occurrences; first: {first.matched_content}",
            remediation=first.remediation,
            reference=first.reference,
            confidence=max(g.confidence for g in group),
            context_note=(
                f"Collapsed from {len(group)} occurrences of {first.rule_id} in "
                f"{first.file_path.name} at lines {shown}. "
                + (first.context_note or "")
            ).strip(),
        ))
    return out


def occurrence_count(finding: Finding) -> int:
    """Return how many raw hits a (possibly collapsed) finding represents."""
    prefix = finding.matched_content.split(" occurrences;", 1)
    if len(prefix) == 2 and prefix[0].isdigit():
        return int(prefix[0])
    return 1


def suppress_redundant(findings: list[Finding]) -> list[Finding]:
    """Drop findings a more precise rule already covers for the same file."""
    by_file: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        by_file[str(f.file_path)].add(f.rule_id)
    return [
        f for f in findings
        if _REDUNDANT_IN_FILE.get(f.rule_id) not in by_file[str(f.file_path)]
    ]


def aggregate_by_file_spread(
    findings: list[Finding], threshold: int = FILE_SPREAD_THRESHOLD,
) -> list[Finding]:
    """Collapse a rule that fires across many files into one skill-level finding."""
    files_per_rule: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        files_per_rule[f.rule_id].append(f)

    out: list[Finding] = []
    emitted: set[str] = set()
    for f in findings:
        group = files_per_rule[f.rule_id]
        distinct_files = {str(g.file_path) for g in group}
        if len(distinct_files) < threshold:
            out.append(f)
            continue
        if f.rule_id in emitted:
            continue
        emitted.add(f.rule_id)

        names = sorted({g.file_path.name for g in group})
        shown = ", ".join(names[:EXAMPLE_FILES])
        if len(names) > EXAMPLE_FILES:
            shown += f", … (+{len(names) - EXAMPLE_FILES} more)"
        total = sum(occurrence_count(g) for g in group)
        first = group[0]

        out.append(Finding(
            rule_id=first.rule_id,
            title=first.title,
            description=first.description,
            severity=_worst([g.severity for g in group]),
            category=first.category,
            file_path=first.file_path,
            line_number=first.line_number,
            matched_content=f"{total} occurrences across {len(distinct_files)} files",
            remediation=first.remediation,
            reference=first.reference,
            confidence=max(g.confidence for g in group),
            context_note=(
                f"{first.rule_id} fires in {len(distinct_files)} files of this skill "
                f"({shown}), so it describes the bundle rather than one file."
            ),
        ))
    return out
