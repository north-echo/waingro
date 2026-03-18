# ClawhHub Ecosystem Security Audit

Static analysis of 30,000+ OpenClaw Agent Skills using WAINGRO.

**Status:** Responsible disclosure in progress. Per-skill findings are embargoed.
Aggregate statistics and methodology are published here.

## Key Findings

| Metric | Value |
|--------|-------|
| Skills scanned | 30,037 |
| Confirmed malicious (TP) | 43 (0.14%) |
| Coordinated C2 campaign | 12 skills across 10 author accounts |
| Reverse shell payloads | 9 skills |
| Jailbreak / safety override | 9 skills |
| Malicious curl-pipe-shell | 13 skills |
| Skills triaged | 589 |
| False positives | 145 |

## Detection Gap

| Detection Method | C2 Skills Detected | Rate |
|-----------------|-------------------|------|
| WAINGRO (format-aware static analysis) | 12/12 | **100%** |
| ClawhHub moderation | 9/12 | 75% |
| VirusTotal | 0/12 | **0%** |

VirusTotal cannot detect instruction-level threats. The malicious intent lives in markdown
text and YAML metadata — natural language instructions telling an AI agent what to do — not
in executable code.

## Documents

- **[methodology.md](methodology.md)** — Scan configuration, triage process, and limitations
- **[data/summary.json](data/summary.json)** — Aggregate scan statistics (no per-skill data)

The full audit report with per-skill findings will be published after the disclosure
window closes (30 days from initial notification, or upon skill removal).

## Tool

[WAINGRO](https://github.com/north-echo/waingro) — AI Agent Skill Security Scanner
