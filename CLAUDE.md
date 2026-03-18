# WAINGRO

AI Agent Skill Security Scanner. Static analysis tool that detects malicious patterns in OpenClaw/Agent Skills format skill files before installation.

Named after the insider threat from Heat (1995).

## Build & Test

```bash
pip install -e ".[dev]"    # Install in dev mode with test/lint deps
pytest -v                  # Run all tests (49 tests)
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

## Current Detection Rules (29 total)

EXEC-001..005 (execution), EXFIL-001..007 (exfiltration), PERSIST-001..004 (persistence), NET-001..004 (network), OBFUSC-001..002 (obfuscation), INJECT-001..003 (injection), SOCIAL-001..003 (social engineering), TYPO-001 (typosquatting)

## v2 Roadmap (not yet built)

- Claude API semantic analysis (agent_loop/cost_watchdog pattern from HANNA)
- SARIF output for DefectDojo/GitHub Advanced Security
- ClawHub API integration for bulk registry scanning
- Shared rule library with HANNA/JUSTINE
