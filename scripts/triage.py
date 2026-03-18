#!/usr/bin/env python3
"""Interactive triage CLI for WAINGRO audit findings.

Displays each flagged skill with its findings and SKILL.md content, prompts
for an analyst verdict, and saves results incrementally.

Usage:
    python scripts/triage.py \
        --input ~/clawhub-corpus/audit_results_v2/triage_tiers/tier1_c2.json \
        --corpus ~/clawhub-corpus/skills/ \
        --output ~/clawhub-corpus/audit_results_v2/triage_results.json

    # Print summary of completed triage
    python scripts/triage.py --summary \
        --output ~/clawhub-corpus/audit_results_v2/triage_results.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

HELP_TEXT = """
Verdict commands:
  TP    — True Positive: genuinely malicious or dangerous behavior
  FP    — False Positive: benign skill, rule fired on legitimate pattern
  SUS   — Suspicious: not definitively malicious, warrants deeper investigation
  SKIP  — Skip for now, come back later
  QUIT  — Save all progress and exit
  FULL  — Show full SKILL.md content (when truncated)
  ?     — Show this help
"""

VALID_VERDICTS = {"TP", "FP", "SUS", "SKIP"}


def load_triage_results(path: Path) -> list[dict]:
    """Load existing triage results, or return empty list."""
    if path.exists():
        with path.open() as f:
            return json.load(f)
    return []


def save_triage_results(path: Path, results: list[dict]) -> None:
    """Save triage results atomically."""
    tmp = path.with_suffix(".json.tmp")
    with tmp.open("w") as f:
        json.dump(results, f, indent=2, default=str)
    tmp.rename(path)


def already_triaged(results: list[dict]) -> set[str]:
    """Build set of already-triaged skill keys (slug:version)."""
    return {f"{r['skill_slug']}:{r.get('skill_version', '')}" for r in results}


def find_skill_md(corpus: Path, skill: dict) -> Path | None:
    """Resolve the SKILL.md path from the skill's scan path or by searching the corpus."""
    # Try the skill_path directly
    skill_path = Path(skill.get("skill_path", ""))
    if (skill_path / "SKILL.md").exists():
        return skill_path / "SKILL.md"

    # Search corpus by slug
    slug = skill["skill_slug"]
    for candidate in corpus.rglob("SKILL.md"):
        if candidate.parent.name == slug:
            return candidate

    return None


def find_bundled_files(skill_dir: Path) -> list[Path]:
    """Find bundled script files in a skill directory."""
    extensions = {".sh", ".py", ".js", ".json"}
    files = []
    for ext in sorted(extensions):
        files.extend(sorted(skill_dir.rglob(f"*{ext}")))
    # Exclude SKILL.md itself
    return [f for f in files if f.name != "SKILL.md"]


def display_skill(skill: dict, index: int, total: int, corpus: Path) -> str | None:
    """Display a skill for triage. Returns full SKILL.md content for FULL command."""
    slug = skill["skill_slug"]
    version = skill.get("skill_version", "unknown")
    verdict_label = skill.get("verdict", "?")
    findings = skill.get("findings", [])
    finding_count = len(findings)

    # Header
    print()
    print("=" * 65)
    print(f" [{index}/{total}] Skill: {slug} (v{version})")
    print(f" ClawhHub: https://clawhub.ai/skills/{slug}")
    print(f" Scanner Verdict: {verdict_label}")
    print(f" Findings: {finding_count}")
    print("=" * 65)

    # Findings sorted by severity
    sorted_findings = sorted(
        findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 99)
    )
    for i, f in enumerate(sorted_findings, 1):
        sev = f.get("severity", "?").upper()
        rule_id = f.get("rule_id", "?")
        title = f.get("title", "")
        matched = f.get("matched_content", "")[:120]
        file_path = f.get("file_path", "")
        line = f.get("line_number")
        loc = Path(file_path).name if file_path else "?"
        if line:
            loc += f":{line}"
        print()
        print(f" FINDING {i}: {rule_id} ({sev})")
        print(f"   {title}")
        print(f"   Location: {loc}")
        print(f"   Match: {matched!r}")

    # Domain analysis if present (Tier 2)
    domain_analysis = skill.get("domain_analysis")
    if domain_analysis:
        print()
        print("-" * 65)
        print(" DOMAIN ANALYSIS:")
        for da in domain_analysis:
            dom = da.get("domain") or "unparseable"
            cls = da.get("classification", "?")
            print(f"   {dom} [{cls}]")

    # SKILL.md content
    skill_md = find_skill_md(corpus, skill)
    full_content = None
    if skill_md and skill_md.exists():
        full_content = skill_md.read_text(encoding="utf-8", errors="replace")
        lines = full_content.split("\n")

        print()
        print("-" * 65)
        print(" SKILL.md CONTENT:")
        print("-" * 65)

        if len(lines) <= 80:
            for ln in lines:
                print(f" {ln}")
        else:
            for ln in lines[:40]:
                print(f" {ln}")
            print(f" [... {len(lines) - 60} lines truncated — type FULL to see all ...]")
            for ln in lines[-20:]:
                print(f" {ln}")

        # Bundled files
        bundled = find_bundled_files(skill_md.parent)
        if bundled:
            print()
            print("-" * 65)
            print(" BUNDLED FILES:")
            print("-" * 65)
            for bf in bundled:
                rel = bf.relative_to(skill_md.parent)
                content = bf.read_text(encoding="utf-8", errors="replace")
                blines = content.split("\n")
                print(f" --- {rel} ({len(blines)} lines) ---")
                if len(blines) <= 40:
                    display_lines = blines
                else:
                    truncated = len(blines) - 30
                    display_lines = blines[:30] + [f" [... {truncated} more lines ...]"]
                for ln in display_lines:
                    print(f"   {ln}")
    else:
        print()
        print(" [SKILL.md not found in corpus]")

    print("-" * 65)
    return full_content


def prompt_verdict(full_content: str | None) -> tuple[str, str]:
    """Prompt for verdict. Returns (verdict, notes)."""
    while True:
        try:
            raw = input(" Verdict? [TP/FP/SUS/SKIP/QUIT/?] > ").strip()
        except (EOFError, KeyboardInterrupt):
            return "QUIT", ""

        if not raw:
            continue

        # Split into command + notes
        parts = raw.split(None, 1)
        cmd = parts[0].upper()
        notes = parts[1] if len(parts) > 1 else ""

        if cmd == "?":
            print(HELP_TEXT)
            continue
        if cmd == "QUIT":
            return "QUIT", ""
        if cmd == "FULL" and full_content:
            print()
            for ln in full_content.split("\n"):
                print(f" {ln}")
            print("-" * 65)
            continue
        if cmd == "FULL" and not full_content:
            print(" [No content available]")
            continue
        if cmd in VALID_VERDICTS:
            return cmd, notes

        print(f" Unknown command: {cmd!r}. Type ? for help.")


def run_triage(input_path: Path, corpus: Path, output_path: Path) -> None:
    """Run interactive triage session."""
    with input_path.open() as f:
        tier_skills = json.load(f)

    results = load_triage_results(output_path)
    done_keys = already_triaged(results)

    # Filter to skills not yet triaged
    pending = [
        s for s in tier_skills
        if f"{s['skill_slug']}:{s.get('skill_version', '')}" not in done_keys
    ]

    total = len(tier_skills)
    already_done = total - len(pending)

    print(f"\nTriage session: {input_path.name}")
    print(f"  Total in tier: {total}")
    print(f"  Already triaged: {already_done}")
    print(f"  Remaining: {len(pending)}")
    print(f"  Output: {output_path}")
    print()

    if not pending:
        print("All skills in this tier have been triaged.")
        return

    for i, skill in enumerate(pending, start=already_done + 1):
        full_content = display_skill(skill, i, total, corpus)
        verdict, notes = prompt_verdict(full_content)

        if verdict == "QUIT":
            print(f"\nProgress saved. {i - already_done - 1} skills triaged this session.")
            return

        result = {
            "skill_slug": skill["skill_slug"],
            "skill_version": skill.get("skill_version", "unknown"),
            "skill_path": skill.get("skill_path", ""),
            "verdict": verdict,
            "analyst_notes": notes,
            "finding_count": skill.get("finding_count", 0),
            "findings": [
                {
                    "rule_id": f.get("rule_id"),
                    "severity": f.get("severity"),
                    "matched_content": f.get("matched_content", "")[:200],
                }
                for f in skill.get("findings", [])
            ],
            "tier_source": input_path.name,
            "triaged_at": datetime.now(tz=UTC).isoformat(),
        }
        results.append(result)
        save_triage_results(output_path, results)

    triaged_this_session = len(pending)
    print(f"\nTier complete. {triaged_this_session} skills triaged this session.")


def print_summary(output_path: Path) -> None:
    """Print triage summary from results file."""
    results = load_triage_results(output_path)
    if not results:
        print("No triage results found.")
        return

    verdicts = {"TP": [], "FP": [], "SUS": [], "SKIP": []}
    by_tier: dict[str, dict[str, int]] = {}

    for r in results:
        v = r.get("verdict", "SKIP")
        verdicts.setdefault(v, []).append(r)
        tier = r.get("tier_source", "unknown")
        if tier not in by_tier:
            by_tier[tier] = {"TP": 0, "FP": 0, "SUS": 0, "SKIP": 0, "total": 0}
        by_tier[tier][v] = by_tier[tier].get(v, 0) + 1
        by_tier[tier]["total"] += 1

    print()
    print("Triage Summary")
    print("=" * 40)
    print(f"Total skills triaged: {len(results)}")
    print(f"  True Positive:  {len(verdicts.get('TP', []))}")
    print(f"  False Positive: {len(verdicts.get('FP', []))}")
    print(f"  Suspicious:     {len(verdicts.get('SUS', []))}")
    print(f"  Skipped:        {len(verdicts.get('SKIP', []))}")
    print()

    print("By tier:")
    for tier, counts in sorted(by_tier.items()):
        t = counts["total"]
        tp = counts.get("TP", 0)
        fp = counts.get("FP", 0)
        sus = counts.get("SUS", 0)
        print(f"  {tier}: {t} triaged, {tp} TP, {fp} FP, {sus} SUS")
    print()

    tps = verdicts.get("TP", [])
    if tps:
        print("True Positives requiring disclosure:")
        for i, r in enumerate(tps, 1):
            slug = r["skill_slug"]
            ver = r.get("skill_version", "?")
            notes = r.get("analyst_notes", "")
            print(f"  {i}. {slug} (v{ver}) — {notes}")
        print()

    suspicious = verdicts.get("SUS", [])
    if suspicious:
        print("Suspicious (needs further investigation):")
        for i, r in enumerate(suspicious, 1):
            slug = r["skill_slug"]
            ver = r.get("skill_version", "?")
            notes = r.get("analyst_notes", "")
            print(f"  {i}. {slug} (v{ver}) — {notes}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Interactive triage CLI for WAINGRO audit")
    parser.add_argument("--input", type=Path, help="Tier JSON file to triage")
    parser.add_argument("--corpus", type=Path, help="Path to skills/ corpus directory")
    parser.add_argument(
        "--output", type=Path, required=True,
        help="Triage results JSON (appended across sessions)",
    )
    parser.add_argument("--summary", action="store_true", help="Print triage summary and exit")
    args = parser.parse_args()

    if args.summary:
        print_summary(args.output.expanduser().resolve())
        return

    if not args.input or not args.corpus:
        print("Error: --input and --corpus required for triage mode", file=sys.stderr)
        sys.exit(1)

    run_triage(
        args.input.expanduser().resolve(),
        args.corpus.expanduser().resolve(),
        args.output.expanduser().resolve(),
    )


if __name__ == "__main__":
    main()
