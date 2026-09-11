![WAINGRO security scanner monitoring a server room](assets/waingro-banner.jpg)

# WAINGRO

AI Agent Security Scanner. Detects malicious patterns in OpenClaw skills and MCP (Model Context Protocol) servers before you install them.

Named after the insider threat from Heat (1995). He ruins everything from the inside. WAINGRO knows one when it sees one.

## Why

Agent tool ecosystems have a trust gap. In February 2026, Bitdefender documented the "ClawHavoc" campaign — coordinated exploitation of the OpenClaw skill ecosystem via malicious skills. In March 2026, we scanned 1,139 MCP servers and found systemic security gaps: 21% access credentials, 13% lack authentication, 9% have path traversal vulnerabilities. Zero tool poisoning — but the implementation bugs are everywhere.

WAINGRO scans both ecosystems from a single tool.

## Install

```bash
pip install git+https://github.com/north-echo/waingro.git
```

Not on PyPI yet.

## Usage

### OpenClaw Skills

```bash
# Scan a skill before installing
waingro scan ./some-skill/

# Scan with JSON output for CI/CD
waingro scan ./some-skill/ --format json --fail-on high

# Write either console or JSON output to a file
waingro scan ./some-skill/ --output report.txt
waingro scan ./some-skill/ --format json --output report.json

# Audit all installed skills
waingro audit ~/skills/
waingro audit ~/skills/ --format json --output audit.json

# Add semantic analysis for skills static rules cannot resolve
waingro scan ./some-skill/ --semantic
```

### Semantic analysis

Static rules cannot tell "block inputs matching this pattern" from "execute this
pattern". That distinction is what separates a security tool from a malicious
skill, and it is the largest source of false positives in this ecosystem: in the
March 2026 ClawHub audit, 20 of 43 initially flagged skills turned out to be
legitimate defensive tools carrying detection signatures.

`--semantic` sends skills that static analysis leaves unresolved (verdict REVIEW
or SUSPICIOUS with a moderate security-tool score) to the Claude API for an
intent judgement. It requires `ANTHROPIC_API_KEY`. Cap spend with
`--semantic-budget`. Skills that static rules already settle are not sent.

### MCP Servers

```bash
# Scan a single MCP server
waingro mcp scan ./mcp-server-github/

# Discover MCP servers from npm, GitHub, and awesome lists
waingro mcp discover --awesome awesome-mcp-servers/README.md -o manifest.json

# Batch scan from discovery manifest
waingro mcp batch manifest.json --results results.json --cleanup
```

### Input and batch safety

- A skill scan accepts a skill directory containing `SKILL.md` or a `SKILL.md`
  file directly. Missing manifests and unrelated files are rejected.
- Bundled files are scanned with their paths preserved in JSON reports. Symlinks
  that resolve outside the skill or MCP server root are not followed.
- Bundled Bash, Zsh, PowerShell, Python, JavaScript, TypeScript, JSON, TOML,
  YAML, Markdown and text files are scanned no more than two directory levels
  below the skill root. The root `SKILL.md` is never double-scanned.
- MCP batch cloning accepts canonical HTTPS GitHub repository URLs only. Clone
  failures and scan timeouts are recorded per server so one bad entry does not
  abort the batch.
- `--cleanup` removes repositories cloned by the current batch invocation. It
  does not remove repositories that were already present in the clone directory.

## Detection Coverage

### OpenClaw Rules (45 rules)

| Rule ID | Category | Severity | Description | Reference |
|---------|----------|----------|-------------|-----------|
| EXEC-001 | Execution | CRITICAL | curl/wget piped to shell | ClawHavoc |
| EXEC-002 | Execution | CRITICAL | Base64-encoded command execution | ClawHavoc |
| EXEC-003 | Execution | HIGH | eval/exec with dynamic content | — |
| EXEC-004 | Execution | CRITICAL | PowerShell download cradles | — |
| EXEC-005 | Execution | CRITICAL | Hex-decoded command execution | — |
| EXEC-006 | Execution | CRITICAL | Hidden execution in bundled scripts | Polymarket trojan |
| EXEC-007 | Supply chain | HIGH | Password-protected remote executable | ATT&CK T1027.013 |
| EXEC-008 | Supply chain | HIGH | Mutable remote instructions executed | ATT&CK T1105 |
| EXEC-009 | Execution | HIGH-CRIT | Remote download, write, chmod, and execute chain | ATT&CK T1105, T1204 |
| EXEC-010 | Execution | HIGH | Audit, authentication, or shell-history log destruction | ATT&CK T1070.002, T1070.003 |
| EXFIL-001 | Exfiltration | HIGH | Credential file access | Bitdefender |
| EXFIL-002 | Exfiltration | CRITICAL | macOS Keychain access | — |
| EXFIL-003 | Exfiltration | HIGH | Browser credential access | — |
| EXFIL-004 | Exfiltration | HIGH | OpenClaw workspace scraping | Bitdefender |
| EXFIL-005 | Exfiltration | HIGH | Environment variable harvesting | — |
| EXFIL-006 | Exfiltration | HIGH | Embedded credential patterns | — |
| EXFIL-007 | Exfiltration | HIGH | Clipboard monitoring | — |
| EXFIL-008 | Exfiltration | HIGH | Sensitive local data transmitted to an external sink | ATT&CK T1041 |
| EXFIL-009 | Exfiltration | MED-HIGH | Sensitive environment value transmitted externally | ATT&CK T1552.001, T1041 |
| EXFIL-010 | Exfiltration | MED-HIGH | Bulk sensitive environment access | ATT&CK T1552.001 |
| PERSIST-001 | Persistence | HIGH | Crontab modification | — |
| PERSIST-002 | Persistence | HIGH | macOS LaunchAgent/LaunchDaemon | — |
| PERSIST-003 | Persistence | HIGH | systemd unit creation | — |
| PERSIST-004 | Persistence | MEDIUM | Shell profile modification | — |
| PERSIST-005 | Persistence | HIGH | Root-owned or privileged world-writable path | CWE-732 |
| NET-001 | Network | CRITICAL | Reverse shell patterns | AuthTool |
| NET-002 | Network | CRITICAL | Known malicious infrastructure | Bitdefender |
| NET-003 | Network | HIGH | Tunnel/proxy setup | — |
| NET-004 | Network | CRITICAL | DNS data exfiltration | — |
| NET-005 | Network | HIGH | Credential transmitted over plaintext transport | CWE-319 |
| NET-006 | Network | MEDIUM | External plaintext WebSocket channel | CWE-319 |
| NET-007 | Network | MEDIUM | Machine identity transmitted to a network sink | ATT&CK T1082 |
| OBFUSC-001 | Obfuscation | CRITICAL | Base64 literal decoded into an execution sink | — |
| OBFUSC-002 | Obfuscation | MEDIUM | String concatenation tricks | — |
| OBFUSC-003 | Obfuscation | HIGH | Machine-obfuscated bundled code | — |
| OBFUSC-004 | Obfuscation | HIGH | Invisible Unicode tag instruction payload | Unicode TR36 |
| INJECT-001 | Injection | HIGH | Prompt injection patterns | — |
| INJECT-002 | Injection | CRITICAL | Jailbreak/DAN patterns | — |
| INJECT-003 | Injection | CRITICAL | Metadata injection | — |
| SOCIAL-001 | Social Engineering | HIGH | Fake dependency installation | 1Password |
| SOCIAL-002 | Social Engineering | HIGH | Fake error messages | ClawHavoc |
| SOCIAL-003 | Social Engineering | CRITICAL | Malicious npm lifecycle hooks | — |
| TYPO-001 | Typosquatting | HIGH | Skill name typosquatting | — |
| BEHAV-001 | Behavioral mismatch | HIGH | Undisclosed high-impact bundled behavior | ATT&CK T1204 |
| BEHAV-002 | Behavioral mismatch | HIGH | Off-purpose high-impact agent instruction | OWASP ASI04 |
| BEHAV-003 | Behavioral mismatch | HIGH | Off-purpose prerequisite data transfer | ATT&CK T1041 |

### MCP Rules (16 rules)

Mapped to [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) and [Adversa AI MCP Security Top 25](https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/).

| Rule ID | Category | Severity | Description | Maps To |
|---------|----------|----------|-------------|---------|
| MCP-001 | Injection | CRITICAL | Tool description prompt injection | OWASP-03, Adversa #3 |
| MCP-002 | Injection | HIGH | Parameter schema injection | Adversa #11 |
| MCP-003 | Obfuscation | CRITICAL | Obfuscated tool handler code | OWASP-05, Adversa #4 |
| MCP-004 | Execution | CRITICAL | Remote code fetch in handlers | OWASP-04, Adversa #4 |
| MCP-005 | Exfiltration | HIGH | Credential file/env access | OWASP-01, Adversa #8 |
| MCP-006 | Exfiltration | HIGH | Sensitive file access | Adversa #8 |
| MCP-007 | Cross-tool | HIGH-CRIT | MCP client config manipulation | Adversa #7 |
| MCP-008 | Network | CRITICAL | Transport exfiltration (tunnels, shells) | Adversa #13 |
| MCP-009 | Supply chain | HIGH | Rug pull indicators (lifecycle hooks) | OWASP-04, Adversa #14 |
| MCP-010 | Scope escalation | HIGH-CRIT | Capabilities beyond stated purpose | OWASP-02, Adversa #19 |
| MCP-011 | Scope escalation | HIGH | Missing authentication | OWASP-07, Adversa #5 |
| MCP-012 | Execution | HIGH | Path traversal patterns | Adversa #10 |
| MCP-013 | Injection | HIGH-CRIT | Tool name spoofing / homoglyphs | Adversa #12 |
| MCP-014 | Network | HIGH | Unsafe network binding (NeighborJack) | Adversa #13 |
| MCP-015 | Injection | MEDIUM | Resource content poisoning surface | Adversa #18 |
| MCP-016 | Supply chain | HIGH | Package name typosquatting | Adversa #14 |

## Reporting model

Findings are graded and aggregated rather than counted per matching line.

- Encoded content is decoded before it is reported. A blob that is not valid
  base64, or that decodes to an image, font or non-text bytes, is not a finding.
- Decode rules require a lexical path from the decoded value to an execution
  sink, either by direct nesting or an exact assigned-name use in the same
  function. Bare decode calls are not findings. Generated, vendored, lock, and
  minified files are excluded from this correlation because a one-line bundle
  cannot establish intent.
- PowerShell cradle findings require downloaded content to reach
  `Invoke-Expression`; mentioning the cmdlet is not enough.
- Cleartext credential findings require a public `http://` endpoint, an
  outbound request, and a credential-bearing value in the same bounded logical
  statement. Local and private-network endpoints are excluded.
- Machine-identity findings follow hostname or network-interface values through
  bounded exact-name assignments to a network send in the same lexical
  function. Local use of a hostname is not a finding.
- Sensitive-file and environment findings require a bounded path from the
  sensitive source to an outbound sink. Provider-matched credential handling
  remains a warning; a provider mismatch or suspicious collection endpoint is
  stronger review evidence.
- Remote execution rules distinguish a documented installer from an opaque
  archive, mutable web instructions, or a download-write-execute chain. The
  remote bytes must be connected to execution; a URL beside a shell keyword is
  not enough.
- Hidden Unicode tag text is decoded for review. The hidden text is evasion
  evidence, while its decoded behavior still determines the final assessment.
- A remote `ws://` endpoint is reported as an exposed bidirectional transport,
  not labeled command-and-control. Intent still requires human review.
- npm lifecycle findings come from parsed `preinstall`, `postinstall`, or
  `prepare` scripts whose command actually fetches content or starts a process.
- Repeats collapse. Many hits of one rule in one file become one finding with
  an occurrence count; a rule firing across four or more files becomes one
  skill-level finding. Nothing is discarded, and severity carries the maximum
  seen in the group.
- Remote fetches are graded by who controls the bytes. `curl https://astral.sh/
  uv/install.sh | sh` is a documented installer; the same line pointed at an
  unrecognised host is not. Vendor domains and installers served from the
  skill's own domain are suppressed, reputable hosts serving user-supplied
  content are reduced, everything else keeps full severity.
- An unrecognised package name is informational. It becomes HIGH only when it
  is one or two edits from a popular package, or claims platform affiliation.

Rule severities are therefore ranges, not constants. `--severity` filters what
you see without changing the underlying verdict or `--fail-on` exit behavior.

The decode-to-execution correlation is intentionally conservative lexical
analysis, not an interprocedural taint engine. Complex aliases, returned values,
callbacks, and cross-function flows may require semantic or manual review.

Scanner verdicts are triage labels, not ground truth. Severity describes impact;
it does not prove intent. `MALICIOUS` is reserved for a direct DNS-exfiltration
chain, or corroborating same-file evidence such as encoded execution or known
command-and-control infrastructure plus execution. Other
high-impact behavior is `SUSPICIOUS`; findings in explicit detection sections,
rule/example literals, and passive test, fixture, benchmark, or evaluation
resources are routed to `REVIEW`. A defensive-looking name never lowers
confidence. Confirm the complete behavior chain and publisher context before
making an attribution.

## Benchmarking

WAINGRO includes a non-executing benchmark command for datasets laid out as
`DATASET/{benign,malicious}/CASE/SKILL.md`:

```bash
waingro benchmark ./dataset --threshold suspicious
waingro benchmark ./dataset --format json --output benchmark.json \
  --fail-under-precision 0.95 --fail-under-recall 0.90
```

On the 100-case [Runtime Skill Audit](https://github.com/tu-tuing/Runtime-Skill-Audit)
dataset at revision `559986985e38f3d8743a217b69e37cb258c9b566`, WAINGRO's
`SUSPICIOUS+` boundary produced 47 true positives, 0 false positives, 50 true
negatives, and 3 false negatives: 100% precision, 94% recall, and 96.9% F1.
The three misses are narrative-only disclosures with no active instruction or
executable dataflow. This is one external dataset, not a claim of universal
performance; keep adding real malicious samples and adversarial benign controls.

## Threat-intelligence model

WAINGRO treats public intelligence in deliberately different ways:

- [MITRE ATT&CK STIX](https://github.com/mitre-attack/attack-stix-data) supplies
  stable behavior vocabulary and technique mappings. ATT&CK labels explain a
  finding; they are not signatures by themselves.
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) is a source
  for non-executed positive fixtures in behavior-chain regression tests. Its
  payloads must never be run as part of a scan.
- [LOLBAS](https://lolbas-project.github.io/api/) and
  [GTFOBins](https://github.com/GTFOBins/GTFOBins.github.io) identify execution
  primitives only after a remote or sensitive value is proven to reach them.
- [URLhaus](https://urlhaus.abuse.ch/api/) and
  [ThreatFox](https://threatfox.abuse.ch/api/) are suitable for optional,
  expiring IOC packs. Indicators need source, license, retrieval time, and
  expiry metadata; stale indicators must not silently become permanent verdicts.
- [Sigma](https://github.com/SigmaHQ/sigma) is useful as a defensive-signature
  corpus and negative fixture source. A skill carrying a detection rule is not
  evidence that it performs the behavior described by that rule.

The intended detection unit is a capability chain—sensitive source or device
identity, optional decode/staging, then network, execution, persistence, or
exfiltration sink. Keyword co-presence is retained only as a review lead and is
not promoted to an attack verdict.

## Research

- [ClawHub Ecosystem Security Audit](research/clawhub-audit/) — March 2026 audit of 30,037 skills
- MCP Ecosystem Security Scan — March 2026 scan of 1,139 MCP servers (paper forthcoming)

Research and maintenance: Christopher Lusk, North Echo Security Research,
clusk@northecho.dev.

## References

- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [Adversa AI MCP Security Top 25](https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/)
- [Vulnerable MCP Project](https://vulnerablemcp.info/)
- [Bitdefender Technical Advisory: OpenClaw Exploitation](https://businessinsights.bitdefender.com/technical-advisory-openclaw-exploitation-enterprise-networks)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [MITRE ATT&CK: System Information Discovery (T1082)](https://attack.mitre.org/techniques/T1082/)
- [OWASP Agentic Skills Top 10](https://owasp.github.io/www-project-agentic-skills-top-10/)
- [Runtime Skill Audit benchmark](https://github.com/tu-tuing/Runtime-Skill-Audit)
- [SkillFortifyBench](https://github.com/qualixar/skillfortifybench)
- [Snyk ToxicSkills](https://github.com/snyk-labs/toxicskills-goof)

## License

MIT
