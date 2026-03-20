#!/usr/bin/env python3
"""Rescan SUS skills with v0.2.0 context scoring + semantic analysis.

Loads SUS skills from triage results, re-scans each with the current
scanner pipeline (context scoring, risk profiles), then runs semantic
analysis on ambiguous cases.

Usage:
    python scripts/rescan_sus.py \
        --triage ~/clawhub-corpus/audit_results_v2/triage_results.json \
        --corpus ~/clawhub-corpus/skills/ \
        --output ~/clawhub-corpus/audit_results_v3/sus_rescan.json \
        --semantic-budget 15.00
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from waingro.analyzers.semantic import SemanticAnalyzer  # noqa: E402
from waingro.models import BundledFileContent  # noqa: E402
from waingro.parsers.script import read_script  # noqa: E402
from waingro.parsers.skill import parse_skill  # noqa: E402
from waingro.scanner import scan_skill  # noqa: E402


def find_skill_path(corpus: Path, slug: str) -> Path | None:
    """Find a skill directory by slug in the corpus."""
    for author_dir in corpus.iterdir():
        if not author_dir.is_dir():
            continue
        skill_dir = author_dir / slug
        if skill_dir.is_dir() and (skill_dir / "SKILL.md").exists():
            return skill_dir
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Rescan SUS skills with v0.2.0")
    parser.add_argument("--triage", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--semantic-budget", type=float, default=15.0)
    parser.add_argument("--dry-run", action="store_true", help="Skip semantic API calls")
    args = parser.parse_args()

    triage_path = args.triage.expanduser().resolve()
    corpus = args.corpus.expanduser().resolve()
    output_path = args.output.expanduser().resolve()

    with triage_path.open() as f:
        triage = json.load(f)

    sus_skills = [r for r in triage if r["verdict"] == "SUS"]
    print(f"SUS skills to rescan: {len(sus_skills)}")

    # Phase 1: Re-scan with v0.2.0 context scoring
    results = []
    not_found = 0
    scan_errors = 0

    for i, sus in enumerate(sus_skills):
        slug = sus["skill_slug"]
        skill_path = find_skill_path(corpus, slug)

        if not skill_path:
            not_found += 1
            results.append({
                "skill_slug": slug,
                "status": "not_found",
                "old_verdict": "SUS",
            })
            continue

        try:
            result = scan_skill(skill_path)
            entry = {
                "skill_slug": slug,
                "skill_path": str(skill_path),
                "status": "scanned",
                "old_verdict": "SUS",
                "new_verdict": result.verdict,
                "security_tool_score": result.security_tool_score,
                "risk_profile": result.risk_profile,
                "finding_count": len(result.findings),
                "high_confidence_findings": len(
                    [f for f in result.findings if f.confidence >= 0.5]
                ),
                "low_confidence_findings": len(
                    [f for f in result.findings if f.confidence < 0.5]
                ),
                "rules_fired": sorted({f.rule_id for f in result.findings}),
                "needs_semantic": False,
                "semantic_result": None,
            }

            # Check if semantic analysis would help
            if (result.verdict in ("REVIEW", "SUSPICIOUS")
                    and 0.3 <= result.security_tool_score <= 0.7):
                    entry["needs_semantic"] = True

            results.append(entry)

        except Exception as e:
            scan_errors += 1
            results.append({
                "skill_slug": slug,
                "status": "error",
                "error": str(e),
                "old_verdict": "SUS",
            })

        if (i + 1) % 50 == 0:
            print(f"  [{i + 1}/{len(sus_skills)}] scanned")

    print("\nPhase 1 complete:")
    scanned = [r for r in results if r["status"] == "scanned"]
    print(f"  Scanned: {len(scanned)}")
    print(f"  Not found: {not_found}")
    print(f"  Errors: {scan_errors}")

    # Verdict distribution after v0.2.0 rescan
    verdicts = {}
    for r in scanned:
        v = r["new_verdict"]
        verdicts[v] = verdicts.get(v, 0) + 1
    print("\n  New verdicts:")
    for v in sorted(verdicts, key=lambda x: verdicts[x], reverse=True):
        print(f"    {v}: {verdicts[v]}")

    needs_semantic = [r for r in scanned if r["needs_semantic"]]
    print(f"\n  Need semantic analysis: {len(needs_semantic)}")

    # Phase 2: Semantic analysis on ambiguous skills
    if needs_semantic and not args.dry_run:
        print(f"\nPhase 2: Running semantic analysis (budget=${args.semantic_budget:.2f})...")
        import os
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            print("  WARNING: ANTHROPIC_API_KEY not set. Skipping semantic analysis.")
        else:
            analyzer = SemanticAnalyzer(
                api_key=api_key, budget=args.semantic_budget,
            )
            semantic_count = 0
            for entry in needs_semantic:
                if analyzer.budget_remaining <= 0:
                    print(f"  Budget exhausted after {semantic_count} skills")
                    break

                skill_path = Path(entry["skill_path"])
                try:
                    skill = parse_skill(skill_path)
                    # Load bundled content
                    for bf in skill.bundled_files:
                        content = read_script(bf)
                        skill.bundled_content.append(
                            BundledFileContent(path=bf, content=content)
                        )

                    result = scan_skill(skill_path)
                    api_result = analyzer.analyze(skill, result.findings)
                    entry["semantic_result"] = api_result

                    classification = api_result.get("skill_classification", "ambiguous")
                    if classification == "malicious":
                        entry["new_verdict"] = "SUSPICIOUS"
                        entry["semantic_upgrade"] = True
                    elif classification == "security_tool":
                        entry["new_verdict"] = "REVIEW"
                        entry["semantic_downgrade"] = True

                    semantic_count += 1
                    if semantic_count % 10 == 0:
                        spent = args.semantic_budget - analyzer.budget_remaining
                        print(f"  [{semantic_count}/{len(needs_semantic)}] "
                              f"${spent:.2f} spent")

                except Exception as e:
                    entry["semantic_error"] = str(e)

            spent = args.semantic_budget - analyzer.budget_remaining
            print(f"\n  Semantic analysis complete: {semantic_count} skills, ${spent:.2f} spent")

    elif needs_semantic and args.dry_run:
        print("\n  Dry run — skipping semantic API calls")

    # Phase 3: Summary
    scanned = [r for r in results if r["status"] == "scanned"]
    final_verdicts = {}
    for r in scanned:
        v = r["new_verdict"]
        final_verdicts[v] = final_verdicts.get(v, 0) + 1

    print(f"\nFinal verdict distribution ({len(scanned)} skills):")
    for v in sorted(final_verdicts, key=lambda x: final_verdicts[x], reverse=True):
        print(f"  {v}: {final_verdicts[v]}")

    # Flag potential new TPs
    potential_tps = [
        r for r in scanned
        if r["new_verdict"] == "MALICIOUS"
        or (r["new_verdict"] == "SUSPICIOUS" and r.get("semantic_upgrade"))
    ]
    if potential_tps:
        print(f"\nPotential new TPs ({len(potential_tps)}):")
        for r in potential_tps:
            print(f"  - {r['skill_slug']} (verdict={r['new_verdict']}, "
                  f"score={r.get('security_tool_score', '?')}, "
                  f"rules={r.get('rules_fired', [])})")

    # Skills that downgraded to CLEAN or REVIEW
    downgraded = [r for r in scanned if r["new_verdict"] in ("CLEAN", "REVIEW")]
    if downgraded:
        print(f"\nDowngraded to CLEAN/REVIEW ({len(downgraded)}):")
        for r in downgraded[:20]:
            print(f"  - {r['skill_slug']} → {r['new_verdict']} "
                  f"(score={r.get('security_tool_score', '?')})")
        if len(downgraded) > 20:
            print(f"  ... and {len(downgraded) - 20} more")

    # Save results
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w") as f:
        json.dump({
            "scan_date": datetime.now(tz=UTC).isoformat(),
            "waingro_version": "0.2.0",
            "total_sus": len(sus_skills),
            "scanned": len(scanned),
            "not_found": not_found,
            "errors": scan_errors,
            "final_verdicts": final_verdicts,
            "potential_new_tps": len(potential_tps),
            "skills": results,
        }, f, indent=2, default=str)

    print(f"\nResults written to {output_path}")


if __name__ == "__main__":
    main()
