# ClawhHub Ecosystem Security Audit

**March 2026** — Static analysis of 30,000+ OpenClaw Agent Skills using WAINGRO.

## Status

- **Disclosure filed:** GHSA-c59g-h434-28gw (private, pending maintainer response)
- **Aggregate data:** Published (this directory)
- **Per-skill findings:** Embargoed pending responsible disclosure (ETA: April 2026)

## Key Numbers

| Metric | Value |
|--------|-------|
| Skills scanned | 30,037 |
| Detection rules | 28 (8 categories) |
| Total findings | 263,693 |
| CRITICAL findings | 4,997 |
| Confirmed malicious (TP) | 43 |
| Coordinated C2 campaign | 12 skills, 10 author accounts |
| Scan duration | 355 seconds (4 workers) |

## Detection Comparison

| Method | C2 Campaign Detection Rate |
|--------|---------------------------|
| WAINGRO (format-aware static analysis) | 100% |
| ClawhHub moderation | 75% |
| VirusTotal | 0% |

VirusTotal cannot detect instruction-level threats. The malicious intent lives
in markdown text and YAML metadata — natural language instructions to an AI
agent — not in executable binary signatures.

## Contents

- [methodology.md](methodology.md) — Data source, scan configuration, triage process, limitations
- [data/summary_public.json](data/summary_public.json) — Aggregate statistics (no per-skill data)
- Full report with per-skill findings will be published after the disclosure window closes

## Tool

WAINGRO is open source: [github.com/north-echo/waingro](https://github.com/north-echo/waingro)

## Contact

Christopher Lusk ([@north-echo](https://github.com/north-echo))
