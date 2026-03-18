#!/usr/bin/env python3
"""Resolve latest version directory for each skill slug in the ClawhHub corpus.

Given a corpus root like ~/clawhub-corpus/skills/, where each slug has version
subdirectories (e.g., skills/weather-check/1.0.0/, skills/weather-check/1.1.0/),
this script finds the highest semver version for each slug and writes one path
per line to an output manifest.

Usage:
    python scripts/resolve_latest.py \
        --corpus ~/clawhub-corpus/skills \
        --output ~/clawhub-corpus/latest_versions.txt
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Matches semver-like strings: 1.0.0, 2.1.3, 0.0.1-beta, etc.
SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


def parse_semver(name: str) -> tuple[int, int, int] | None:
    """Extract (major, minor, patch) from a directory name, or None."""
    m = SEMVER_RE.match(name)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None


def resolve_latest_version(slug_dir: Path) -> Path | None:
    """Find the latest version directory under a skill slug directory.

    Priority:
    1. Highest semver directory
    2. Directory named "latest" (fallback)
    3. Only child directory (single version)
    4. None if empty or no valid versions
    """
    if not slug_dir.is_dir():
        return None

    children = [c for c in slug_dir.iterdir() if c.is_dir()]
    if not children:
        # No version subdirs — check if SKILL.md is directly in slug dir
        if (slug_dir / "SKILL.md").exists():
            return slug_dir
        return None

    # Try semver resolution
    versioned = []
    latest_dir = None
    for child in children:
        sv = parse_semver(child.name)
        if sv:
            versioned.append((sv, child))
        elif child.name == "latest":
            latest_dir = child

    if versioned:
        versioned.sort(key=lambda x: x[0], reverse=True)
        return versioned[0][1]

    if latest_dir:
        return latest_dir

    # Single child directory — use it
    if len(children) == 1:
        return children[0]

    # Multiple non-semver dirs — pick alphabetically last as best guess
    return sorted(children, key=lambda c: c.name)[-1]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Resolve latest version for each ClawhHub skill slug"
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

    slugs = sorted(d for d in corpus.iterdir() if d.is_dir())
    resolved = []
    skipped = []

    for slug_dir in slugs:
        latest = resolve_latest_version(slug_dir)
        if latest and (latest / "SKILL.md").exists():
            resolved.append(latest)
        else:
            skipped.append(slug_dir.name)

    # Write manifest
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w") as f:
        for path in resolved:
            f.write(f"{path}\n")

    print(f"Resolved {len(resolved)} latest versions from {len(slugs)} slugs")
    if skipped:
        print(f"Skipped {len(skipped)} slugs (no SKILL.md found)")
        if len(skipped) <= 20:
            for s in skipped:
                print(f"  - {s}")
        else:
            for s in skipped[:10]:
                print(f"  - {s}")
            print(f"  ... and {len(skipped) - 10} more")


if __name__ == "__main__":
    main()
