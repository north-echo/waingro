# Audit Methodology

## Data Source

The `openclaw/skills` GitHub repository is an official archive of every version
of every skill published to ClawHub. We cloned it (`git clone --depth 1`) on
March 18, 2026 and scanned every directory containing a SKILL.md file.

- **Corpus:** openclaw/skills GitHub archive
- **Snapshot date:** 2026-03-18
- **Total skills scanned:** 30,037 (latest version of each skill only)
- **Unique authors:** ~12,000

We scanned only the latest version of each skill, reflecting what users
actually install. Historical version analysis is a future work item.

## Scanner

WAINGRO v0.1.0 — a static analysis tool purpose-built for the OpenClaw Agent
Skills format. It parses:

- YAML frontmatter (skill metadata)
- Markdown body (agent instructions)
- Fenced code blocks (embedded commands)
- Bundled scripts (.sh, .py, .js, .json files in the skill directory)

28 detection rules across 8 categories:

| Category | Rules | Description |
|----------|-------|-------------|
| Execution | EXEC-001..005 | curl-pipe-shell, base64/hex encoded commands, eval/exec, PowerShell cradles |
| Exfiltration | EXFIL-001..007 | Credential files, Keychain, browser creds, workspace scraping, env harvesting, clipboard |
| Persistence | PERSIST-001..004 | Crontab, LaunchAgent, systemd, shell profile modification |
| Network / C2 | NET-001..004 | Reverse shells, known C2 IPs, tunnels, DNS exfiltration |
| Obfuscation | OBFUSC-001..002 | Base64 strings, string concatenation evasion |
| Injection | INJECT-001..003 | Prompt injection, jailbreak/DAN, metadata injection |
| Social Engineering | SOCIAL-001..003 | Fake dependencies, fake errors, npm lifecycle hooks |
| Typosquatting | TYPO-001 | Skill name similarity to known-good skills |

## Scan Execution

- **Platform:** ThinkCentre M720q (x86_64, Python 3.14)
- **Parallelism:** 4 workers via ProcessPoolExecutor
- **Duration:** 355 seconds
- **Parse errors:** 17 skills failed to parse (logged, not counted as findings)

## Triage

Findings were split into priority tiers for manual review:

- **Tier 1 (exhaustive review):** Skills with NET-002 (known C2 IPs), NET-001
  (reverse shells), or INJECT-002 (jailbreak/DAN patterns). ~123 skills.
- **Tier 2 (domain-filtered review):** Skills with EXEC-001 (curl-pipe-shell),
  filtered by domain reputation. Known-safe domains (github.com, brew.sh,
  nodejs.org, etc.) excluded. Remaining unknown/suspicious domains reviewed.
- **Tier 3 (sample-based review):** Skills with EXEC-003 (eval/exec) or
  EXFIL-005/006/007 not already in Tier 1/2. Sampled for review.
- **Tier 4 (skipped):** Skills whose only findings are high-FP-rate rules
  (OBFUSC-001, EXFIL-001, EXFIL-004, SOCIAL-001, PERSIST-004). Aggregate
  stats only.

Total skills triaged: 589. Verdicts: 43 TP, 145 FP, 401 Suspicious (awaiting
deeper manual review).

## Limitations

1. **Static analysis only.** No dynamic execution, sandbox analysis, or
   semantic AI analysis of skill behavior.
2. **OBFUSC-001 noise.** The base64 string detection rule produced 175,370
   findings (66.5% of all findings). The 40-character threshold matches SHA
   hashes, UUIDs, and URL paths. Rule tuning is planned.
3. **Incomplete triage.** 401 skills are marked Suspicious but not yet manually
   reviewed. The true TP count is likely higher than 43.
4. **Latest versions only.** Historical versions were not scanned. A skill
   could have been malicious in a prior version and clean now (or vice versa).
5. **No API-based semantic analysis.** A future audit phase will use Claude API
   to analyze skill instructions for semantic intent beyond pattern matching.
