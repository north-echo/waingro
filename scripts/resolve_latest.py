#!/usr/bin/env python3
"""Build a scan manifest from a ClawhHub skills corpus.

The openclaw/skills archive uses the structure:
    skills/<author>/<skill-name>/SKILL.md
    skills/<author>/<skill-name>/scripts/...

This script finds every directory containing a SKILL.md and writes one path
per line to a manifest file for use with bulk_scan.py.

Usage:
    python scripts/resolve_latest.py \
        --corpus ~/clawhub-corpus/skills \
        --output ~/clawhub-corpus/latest_versions.txt
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def find_skill_dirs(corpus: Path) -> list[Path]:
    """Find all directories containing a SKILL.md file.

    Returns the parent directory of each SKILL.md, deduplicated.
    If a skill directory contains nested SKILL.md files (e.g. in subdirectories),
    only the shallowest one is included.
    """
    skill_dirs: list[Path] = []
    seen_parents: set[Path] = set()

    for skill_md in sorted(corpus.rglob("SKILL.md")):
        skill_dir = skill_md.parent

        # Skip if this dir is a child of an already-included skill dir
        # (e.g., a SKILL.md inside a scripts/ subdirectory)
        if any(skill_dir != p and str(skill_dir).startswith(str(p) + "/") for p in seen_parents):
            continue

        skill_dirs.append(skill_dir)
        seen_parents.add(skill_dir)

    return skill_dirs


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build scan manifest from ClawhHub skills corpus"
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        required=True,
        help="Path to skills/ directory (e.g., ~/clawhub-corpus/skills)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output manifest file (one path per line)",
    )
    args = parser.parse_args()

    corpus = args.corpus.expanduser().resolve()
    if not corpus.is_dir():
        print(f"Error: corpus directory does not exist: {corpus}", file=sys.stderr)
        sys.exit(1)

    skill_dirs = find_skill_dirs(corpus)

    # Write manifest
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w") as f:
        for path in skill_dirs:
            f.write(f"{path}\n")

    # Count authors (depth-1 directories in corpus)
    authors = {
        p.relative_to(corpus).parts[0]
        for p in skill_dirs
        if len(p.relative_to(corpus).parts) >= 2
    }

    print(f"Found {len(skill_dirs)} skills from {len(authors)} authors")
    print(f"Manifest written to {args.output}")


if __name__ == "__main__":
    main()
