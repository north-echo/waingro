#!/usr/bin/env python3
"""Bulk scan pipeline for ClawHub ecosystem audit.

Reads a manifest of skill paths (one per line) and runs WAINGRO's scan_skill()
against each. Produces three output files:
  - all_findings.jsonl  (one JSON line per finding)
  - summary.json        (aggregate statistics)
  - flagged_skills.json (full results for skills with ≥1 finding)
  - parse_errors.log    (skills that failed to parse)

Usage:
    python scripts/bulk_scan.py \
        --manifest ~/clawhub-corpus/latest_versions.txt \
        --output ~/clawhub-corpus/audit_results/ \
        --workers 4
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

# Ensure waingro is importable when run from repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from waingro.scanner import scan_skill  # noqa: E402


def scan_one(skill_path_str: str) -> dict:
    """Scan a single skill and return a serializable result dict.

    Runs in a worker process — must be a top-level function for pickling.
    """
    skill_path = Path(skill_path_str)
    try:
        result = scan_skill(skill_path)
        findings = []
        for f in result.findings:
            findings.append({
                "rule_id": f.rule_id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "category": f.category.value,
                "file_path": str(f.file_path),
                "line_number": f.line_number,
                "matched_content": f.matched_content,
                "remediation": f.remediation,
                "reference": f.reference,
            })

        # Extract slug and version from path
        # Expected structure: .../skills/<slug>/<version>/
        parts = skill_path.parts
        slug = parts[-2] if len(parts) >= 2 else skill_path.name
        version = parts[-1] if len(parts) >= 2 else "unknown"
        # If the path is the slug dir itself (no version subdir), adjust
        if (skill_path / "SKILL.md").exists() and version == skill_path.name:
            slug = skill_path.name
            version = "unknown"

        return {
            "status": "ok",
            "skill_path": str(skill_path),
            "skill_slug": slug,
            "skill_version": result.metadata.version or version,
            "skill_name": result.metadata.name,
            "verdict": result.verdict,
            "finding_count": len(findings),
            "findings": findings,
            "files_scanned": result.files_scanned,
            "rules_evaluated": result.rules_evaluated,
        }
    except Exception as exc:
        return {
            "status": "error",
            "skill_path": str(skill_path),
            "error": f"{type(exc).__name__}: {exc}",
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Bulk scan ClawHub skills with WAINGRO")
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Manifest file with one skill path per line",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output directory for results",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of parallel workers (default: 4)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit to first N skills (0 = all, useful for testing)",
    )
    args = parser.parse_args()

    manifest = args.manifest.expanduser().resolve()
    if not manifest.exists():
        print(f"Error: manifest not found: {manifest}", file=sys.stderr)
        sys.exit(1)

    skill_paths = [line.strip() for line in manifest.read_text().splitlines() if line.strip()]
    if args.limit > 0:
        skill_paths = skill_paths[: args.limit]

    total = len(skill_paths)
    print(f"Scanning {total} skills with {args.workers} workers...")

    output_dir = args.output.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    findings_path = output_dir / "all_findings.jsonl"
    flagged_path = output_dir / "flagged_skills.json"
    summary_path = output_dir / "summary.json"
    errors_path = output_dir / "parse_errors.log"

    # Set up error logging
    logging.basicConfig(
        filename=str(errors_path),
        level=logging.ERROR,
        format="%(asctime)s %(message)s",
    )

    start_time = time.monotonic()
    completed = 0
    results_all = []

    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(scan_one, p): p for p in skill_paths}

        for future in as_completed(futures):
            result = future.result()
            results_all.append(result)
            completed += 1

            if result["status"] == "error":
                logging.error("%s: %s", result["skill_path"], result["error"])

            if completed % 1000 == 0 or completed == total:
                elapsed = time.monotonic() - start_time
                rate = completed / elapsed if elapsed > 0 else 0
                print(f"  [{completed}/{total}] {rate:.0f} skills/sec")

    duration = time.monotonic() - start_time

    # Separate successes and errors
    ok_results = [r for r in results_all if r["status"] == "ok"]
    error_results = [r for r in results_all if r["status"] == "error"]

    # Write all_findings.jsonl
    with findings_path.open("w") as f:
        for r in ok_results:
            for finding in r["findings"]:
                line = {
                    "skill_slug": r["skill_slug"],
                    "skill_version": r["skill_version"],
                    **finding,
                }
                f.write(json.dumps(line, default=str) + "\n")

    # Write flagged_skills.json
    flagged = [r for r in ok_results if r["finding_count"] > 0]
    flagged.sort(key=lambda r: r["finding_count"], reverse=True)
    with flagged_path.open("w") as f:
        json.dump(flagged, f, indent=2, default=str)

    # Compute aggregate stats
    findings_by_severity: dict[str, int] = {}
    findings_by_rule: dict[str, int] = {}
    findings_by_category: dict[str, int] = {}
    total_findings = 0

    for r in ok_results:
        for finding in r["findings"]:
            total_findings += 1
            sev = finding["severity"]
            findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1
            rid = finding["rule_id"]
            findings_by_rule[rid] = findings_by_rule.get(rid, 0) + 1
            cat = finding["category"]
            findings_by_category[cat] = findings_by_category.get(cat, 0) + 1

    # Sort rule counts descending
    findings_by_rule = dict(sorted(findings_by_rule.items(), key=lambda x: x[1], reverse=True))

    clean_count = sum(1 for r in ok_results if r["verdict"] == "CLEAN")
    flagged_count = len(flagged)
    flagged_pct = (flagged_count / len(ok_results) * 100) if ok_results else 0

    top_20 = [
        {"skill_slug": r["skill_slug"], "finding_count": r["finding_count"],
         "verdict": r["verdict"]}
        for r in flagged[:20]
    ]

    summary = {
        "scan_metadata": {
            "scan_date": datetime.now(tz=UTC).isoformat(),
            "waingro_version": "0.1.0",
            "rule_count": ok_results[0]["rules_evaluated"] if ok_results else 0,
            "corpus_source": "openclaw/skills (github archive)",
            "total_skills_scanned": len(ok_results),
            "parse_errors": len(error_results),
            "scan_duration_seconds": round(duration, 1),
            "workers": args.workers,
        },
        "aggregate": {
            "clean_skills": clean_count,
            "flagged_skills": flagged_count,
            "flagged_percentage": round(flagged_pct, 2),
            "total_findings": total_findings,
            "findings_by_severity": findings_by_severity,
            "findings_by_rule_id": findings_by_rule,
            "findings_by_category": findings_by_category,
            "top_20_most_flagged_skills": top_20,
        },
    }

    with summary_path.open("w") as f:
        json.dump(summary, f, indent=2)

    # Print summary
    print(f"\nScan complete in {duration:.1f}s")
    print(f"  Skills scanned: {len(ok_results)}")
    print(f"  Parse errors:   {len(error_results)}")
    print(f"  Clean:          {clean_count}")
    print(f"  Flagged:        {flagged_count} ({flagged_pct:.1f}%)")
    print(f"  Total findings: {total_findings}")
    print(f"\nOutput written to {output_dir}/")


if __name__ == "__main__":
    main()
