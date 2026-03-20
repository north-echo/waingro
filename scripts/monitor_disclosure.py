#!/usr/bin/env python3
"""Monitor whether disclosed malicious skills have been removed from ClawHub.

Usage:
    python scripts/monitor_disclosure.py \
        --output ~/clawhub-corpus/audit_results_v2/disclosure_monitor.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

CLAWHUB_SKILL_URL = "https://clawhub.ai/skills/{slug}"

# 8 live ClawHavoc C2 skills + 2 Polymarket trojan
MONITORED_SKILLS = [
    {"slug": "secureclaw-skill", "campaign": "ClawHavoc C2"},
    {"slug": "openclaw-defender", "campaign": "ClawHavoc C2"},
    {"slug": "openclaw-skill-scanner", "campaign": "ClawHavoc C2"},
    {"slug": "skill-auditor-v2", "campaign": "ClawHavoc C2"},
    {"slug": "skill-security-auditor", "campaign": "ClawHavoc C2"},
    {"slug": "openclaw-skill-auditor", "campaign": "ClawHavoc C2"},
    {"slug": "skill-auditor-pro", "campaign": "ClawHavoc C2"},
    {"slug": "sec-audit", "campaign": "ClawHavoc C2"},
    {"slug": "better-polymarket", "campaign": "Polymarket trojan"},
    {"slug": "polymarket-all-in-one", "campaign": "Polymarket trojan"},
]


def check_skill(slug: str) -> tuple[str, int]:
    """Check if a skill is still live on ClawHub. Returns (status, http_code)."""
    url = CLAWHUB_SKILL_URL.format(slug=slug)
    req = Request(url, method="HEAD")  # noqa: S310
    req.add_header("User-Agent", "WAINGRO-Monitor/0.3.0")
    try:
        with urlopen(req, timeout=15) as resp:  # noqa: S310
            return ("LIVE", resp.status)
    except HTTPError as e:
        if e.code == 404:
            return ("REMOVED", 404)
        return ("ERROR", e.code)
    except (URLError, TimeoutError):
        return ("ERROR", 0)


def main() -> None:
    parser = argparse.ArgumentParser(description="Monitor disclosed malicious skills")
    parser.add_argument(
        "--output", type=Path, required=True,
        help="JSONL log file (appended)",
    )
    args = parser.parse_args()

    output = args.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(tz=UTC).isoformat()
    results = []
    removed = 0
    live = 0

    for skill in MONITORED_SKILLS:
        status, code = check_skill(skill["slug"])
        entry = {
            "timestamp": timestamp,
            "slug": skill["slug"],
            "campaign": skill["campaign"],
            "status": status,
            "http_code": code,
        }
        results.append(entry)
        if status == "REMOVED":
            removed += 1
        elif status == "LIVE":
            live += 1

    # Append to JSONL
    with output.open("a") as f:
        for entry in results:
            f.write(json.dumps(entry) + "\n")

    # Print summary
    print(f"[{timestamp}] Checked {len(MONITORED_SKILLS)} skills: "
          f"{live} live, {removed} removed, {len(results) - live - removed} errors")
    for r in results:
        icon = {"LIVE": "!!", "REMOVED": "OK", "ERROR": "??"}[r["status"]]
        print(f"  [{icon}] {r['slug']} ({r['campaign']}): {r['status']} ({r['http_code']})")

    # Exit 0 if any removed (progress), 1 if all still live
    sys.exit(0 if removed > 0 else 1)


if __name__ == "__main__":
    main()
