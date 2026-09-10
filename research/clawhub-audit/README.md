# ClawHub Ecosystem Security Audit

**March 2026** — Static analysis of 30,000+ OpenClaw Agent Skills using WAINGRO.

## Status

- **Disclosure filed:** 2026-03-18 as GHSA-c59g-h434-28gw against `openclaw/clawhub`.
  Reporter credit accepted 2026-03-18. Severity Critical (CVSS 9.6), CWE-506 and
  CWE-829. No CVE assigned.
- **Outcome:** Closed 2026-04-06 as **out of scope** for `openclaw/clawhub`. The
  maintainer's position was that the repository contains no skill registry logic
  or `SKILL.md` files, and asked for the report to be refiled against
  `openclaw/skills`. The advisory was never published, so it is not retrievable
  from the GitHub advisory API. The findings themselves were not disputed on the
  merits; the report was never triaged against the registry.
- **Refiling:** not possible as advised. The `openclaw/skills` repository no
  longer exists, so the archive this audit scanned and the disclosure target the
  maintainer named are both gone.
- **Aggregate data:** Published (this directory)
- **Per-skill findings:** Still unpublished. The stated Day 30 window lapsed on
  2026-04-17. Publication is a pending decision, not an active embargo.

## Key Numbers

| Metric | Value |
|--------|-------|
| Skills scanned | 30,037 |
| Detection rules | 28 (8 categories) |
| Total findings | 263,693 |
| CRITICAL findings | 4,997 |
| Confirmed malicious (TP) | 25 |
| Coordinated C2 campaign | 12 skills, 10 author accounts |
| Trojanized tool (hidden backdoor) | 2 skills |
| Reverse shell payloads | 9 skills |
| Independent campaigns identified | 2 |
| Reclassified as FP (security tools) | 20 |
| Scan duration | 355 seconds (4 workers) |

## Detection Comparison

| Method | C2 Campaign Detection Rate |
|--------|---------------------------|
| WAINGRO (format-aware static analysis) | 100% |
| ClawHub moderation | 75% |
| VirusTotal | 0% |

VirusTotal cannot detect instruction-level threats. The malicious intent lives
in markdown text and YAML metadata — natural language instructions to an AI
agent — not in executable binary signatures.

## Contents

- [methodology.md](methodology.md) — Data source, scan configuration, triage process, limitations
- [data/summary_public.json](data/summary_public.json) — Aggregate statistics (no per-skill data)
- Full report with per-skill findings: unpublished, pending a decision (see Status)

## Tool

WAINGRO is open source: [github.com/north-echo/waingro](https://github.com/north-echo/waingro)

## Contact

Christopher Lusk ([@north-echo](https://github.com/north-echo))
