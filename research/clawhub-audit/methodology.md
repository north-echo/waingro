# ClawhHub Audit Methodology

## Scanner

**WAINGRO v0.1.0** — format-aware static analysis for OpenClaw Agent Skills. Parses SKILL.md
files (YAML frontmatter, markdown body, fenced code blocks) and bundled scripts (.sh, .py,
.js, .json). Runs 28 detection rules across 8 threat categories.

Source: https://github.com/north-echo/waingro

## Corpus

The `openclaw/skills` GitHub repository is an official archive of every skill published to
ClawhHub. We cloned it (`git clone --depth 1`) on March 18, 2026, and scanned every directory
containing a `SKILL.md` file.

- **Skills scanned:** 30,037
- **Unique authors:** ~12,000
- **Parse errors:** 17
- **Scan duration:** 355 seconds (4 parallel workers)
- **Platform:** ThinkCentre M720q (x86_64, Fedora, Python 3.14)

## Triage

Findings were split into priority tiers:

- **Tier 1 (exhaustive review):** Skills with C2 IP references (NET-002), reverse shell
  patterns (NET-001), or jailbreak patterns (INJECT-002). 52 unique skills.
- **Tier 2 (domain-filtered):** Skills with curl-pipe-shell patterns (EXEC-001). 524 total,
  filtered to 338 after removing known-safe domains (github.com, brew.sh, etc.).
- **Tier 3 (sampled):** Skills with eval/exec (EXEC-003) or credential exfiltration patterns
  (EXFIL-005/006/007). Sampled 200 from ~1,000.
- **Tier 4 (noise — skipped):** Skills whose only findings came from high-FP-rate rules
  (OBFUSC-001, EXFIL-001, EXFIL-004, SOCIAL-001, PERSIST-004). 26,313 skills.

Total skills triaged: 589 (automated heuristics + manual review of Tier 1).

## Triage Verdicts

- **True Positive (TP):** Genuinely malicious or dangerous behavior confirmed
- **False Positive (FP):** Benign skill, rule fired on legitimate pattern (e.g., security
  tools embedding detection signatures)
- **Suspicious (SUS):** Not definitively malicious, warrants deeper investigation

## Limitations

- Static analysis only — no dynamic execution or semantic AI analysis
- OBFUSC-001 (base64 string detection) has a high false positive rate (66.5% of all findings)
  and needs threshold tuning
- Tier 2/3 triage used automated heuristics; full manual review would likely surface
  additional TPs from the 401 SUS skills
- Some skill directories in the archive had no SKILL.md (299 skipped)
- The corpus represents a point-in-time snapshot; skills may have been added or removed since

## Detection Rules

28 rules across 8 categories:

| Category | Rules | Severity Range |
|----------|-------|---------------|
| Execution | EXEC-001..005 | CRITICAL–HIGH |
| Exfiltration | EXFIL-001..007 | CRITICAL–HIGH |
| Persistence | PERSIST-001..004 | HIGH–MEDIUM |
| Network | NET-001..004 | CRITICAL–HIGH |
| Obfuscation | OBFUSC-001..002 | MEDIUM |
| Injection | INJECT-001..003 | CRITICAL–HIGH |
| Social Engineering | SOCIAL-001..003 | CRITICAL–HIGH |
| Typosquatting | TYPO-001 | HIGH |
