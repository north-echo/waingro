# WAINGRO

AI Agent Skill Security Scanner. Static analysis tool that detects malicious patterns in OpenClaw/Agent Skills format skill files before installation.

Named after the insider threat from Heat (1995).

## Build & Test

```bash
pip install -e ".[dev]"    # Install in dev mode with test/lint deps
pytest -v                  # Run all tests (166 tests)
ruff check .               # Lint (must pass clean)
```

## CLI Usage

```bash
waingro scan <skill-dir-or-SKILL.md>              # Console output
waingro scan <path> --format json                  # JSON output
waingro scan <path> --fail-on critical             # Exit 1 if critical findings
waingro audit <directory-of-skills>                # Bulk scan all skills in dir
waingro version                                    # Print version
```

## Architecture

- **Parsers** (`src/waingro/parsers/`) — Extract YAML frontmatter, markdown body, code blocks, and bundled script files from skill directories
- **Rules** (`src/waingro/rules/`) — Detection rules using `Rule` ABC with `@register_rule` decorator. Each rule implements `evaluate(ParsedSkill) -> list[Finding]`
- **Analyzers** (`src/waingro/analyzers/`) — `static.py` runs all registered rules; `typosquat.py` checks skill names against known-good list via Levenshtein distance
- **Scanner** (`src/waingro/scanner.py`) — Orchestrator: parse -> analyze -> produce `ScanResult`
- **Reporters** (`src/waingro/reporters/`) — Console (Rich) and JSON output formatters
- **CLI** (`src/waingro/cli.py`) — Click CLI entry point

## Adding a New Rule

1. Add a class to the appropriate file in `src/waingro/rules/` (or create a new module)
2. Decorate with `@register_rule`
3. Set `rule_id`, `title`, `description` as class attributes
4. Implement `evaluate()` returning `list[Finding]`
5. The rule is auto-discovered — no wiring needed beyond the import in `analyzers/static.py` (add import if new module)
6. Add a test fixture in `tests/fixtures/malicious/` and a test in `tests/test_rules/`

Rule ID format: `CATEGORY-NNN` (e.g., `EXEC-005`, `EXFIL-005`)

## Conventions

- **pathlib throughout** — no `os.path`
- **Python 3.11+** compat (primary target 3.14)
- **ruff** for linting: line length 100, select E/F/I/N/W/UP/B/SIM/S
- **S101/S108 suppressed** in tests (assert and /tmp usage are expected)
- Test fixtures use `example.com` and `127.0.0.1` only — no real malicious infrastructure
- Verdicts: CLEAN (no findings), WARNING (medium/low), SUSPICIOUS (high), MALICIOUS (critical)

## Current Detection Rules (28 total)

EXEC-001..005 (execution), EXFIL-001..007 (exfiltration), PERSIST-001..004 (persistence), NET-001..004 (network), OBFUSC-001..002 (obfuscation), INJECT-001..003 (injection), SOCIAL-001..003 (social engineering), TYPO-001 (typosquatting)

## Audit Scripts (`scripts/`)

- `resolve_latest.py` — Build scan manifest from ClawhHub corpus (finds all SKILL.md dirs)
- `bulk_scan.py` — Parallel bulk scanner with JSONL/JSON output
- `triage_prep.py` — Split findings into priority tiers with domain extraction
- `triage.py` — Interactive triage CLI (resume-safe, multi-session)
- `auto_triage.py` — Automated triage with analyst heuristics
- `generate_report.py` — Generate audit report, executive summary, and disclosure package

## ClawhHub Audit Results

First audit completed March 2026: 30,037 skills scanned, 43 confirmed TPs including a 12-skill C2 campaign (ClawHavoc). Disclosure filed as GHSA-c59g-h434-28gw on openclaw/clawhub (2026-03-18). Aggregate data published in `research/clawhub-audit/`. Per-skill findings embargoed until 2026-04-17 or maintainer remediation. Audit data lives on hanna2 at `~/clawhub-corpus/audit_results_v2/`.

## v2 Roadmap (not yet built)

- OBFUSC-001 rule tuning (reduce 66% FP rate — raise threshold, exclude SHA/UUID patterns)
- Claude API semantic analysis (agent_loop/cost_watchdog pattern from HANNA)
- SARIF output for DefectDojo/GitHub Advanced Security
- Shared rule library with HANNA/JUSTINE
