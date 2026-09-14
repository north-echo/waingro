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

- Default skill and benchmark scans are static: WAINGRO reads candidate files
  but does not import, execute, install, or contact dependencies declared by
  them. The optional `--semantic` mode separately sends unresolved text to the
  configured model API.
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

### Provenance review

WAINGRO can prepare an artifact-bound provenance ledger from an unauthorized
manual-review queue without contacting a network or executing candidate code:

```bash
waingro provenance prepare queue.json --output provenance.json
waingro provenance apply-review provenance.json reviews.json \
  --output provenance-reviewed.json
```

`prepare` re-scans every candidate, requires its exact SHA-256 identity to
match, checks registry identity, inventories declared source repositories and
service hosts, and flags content-equivalent queue entries without merging their
publishers. `apply-review` accepts separately gathered source-history evidence
only when it is bound to a ledger artifact and a full Git revision. Neither
command installs, imports, executes, or authorizes a candidate, and external
source corroboration never changes an intent verdict.

### Dynamic case safety

A pre-execution case dossier can be verified without creating a runnable plan,
transferring a candidate, or starting a VM:

```bash
waingro dynamic check-case deploy/hanna2/cases/clawgrid-connector/case.json
waingro dynamic check-case deploy/hanna2/cases/clawgrid-connector/case.json \
  --candidate /path/to/exact/clawgrid-connector
waingro dynamic check-controls deploy/hanna2/control-suite.json
```

The optional candidate check is static and artifact-bound. A valid case must
keep its execution, corpus, and transfer authorization gates false; omit a
selected entrypoint; pin every inert JSON fixture; require containment controls;
and retain at least one unresolved blocker. Case validation always reports
`ready_for_execution: false`.

WAINGRO 0.11.0 adds plan-bound containment primitives for later KVM-only
validation: an immutable OpenClaw skill alias, read-only digest-bound synthetic
JSON, root-owned no-op `openclaw` and `crontab` shims, and an in-guest DNS plus
HTTP(S) sinkhole. A fixed JSON response is served only for its exact host, TLS
SNI name, method, path, digest, and size. The guest refuses to install a shim if
the corresponding real command exists. Candidate output, process count, file
size, trace size, wall time, overlay allocation, and host free space remain
bounded.

`check-controls` verifies a 14-control, digest-pinned benign catalog and always
reports both transfer and execution as unauthorized. The controls cover benign
and negative behavior, sinkhole DNS/HTTPS, inert command interception, timeout,
output limiting, resource-policy rejection, missing capabilities, plan/image
tampering, trace trust, before/after posture, and guest cleanup. The full suite
passed on the dedicated hanna2 host on September 14, 2026. No corpus candidate
was transferred or executed; see the
[hanna2 control-validation report](research/hanna2-control-validation-2026-09-14.md).

The dedicated hanna2 lab now uses a clean Fedora Server 44 installation with
the prior data/backup disk physically disconnected, SELinux enforcing, a
management-only inbound firewall, key-only SSH, separate no-exec work and image
filesystems, and a digest-pinned Fedora 44 KVM base image. Host egress activation
uses a per-boot 120-second rollback timer: the containment marker is not trusted
until the operator reconnects and explicitly commits it. Preflight also rejects
a world-accessible KVM device, a missing IOMMU, or a lockdown marker that has
not been committed. It also machine-enforces Secure Boot instead of relying on
an operator checklist; host provisioning separately rejects audit task
suppression. Secure Boot was enabled and verified on September 14, 2026. The
pending UEFI key and revocation-database updates remain blocking because Lenovo
firmware rejects their authenticated runtime writes; complete them from
firmware setup and repeat the complete benign suite before any corpus execution.

## Detection Coverage

### OpenClaw Rules (48 rules)

| Rule ID | Category | Severity | Description | Reference |
|---------|----------|----------|-------------|-----------|
| AGENT-001 | Agent control | HIGH | Remote service granted priority, silent execution authority, and owner-output suppression | OWASP ASI04 |
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
| EXEC-011 | Supply chain | MEDIUM | Automatic unpinned npx-like package execution | CWE-829, GHSA-jxh8-jh77-xh6g |
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
| BEHAV-004 | Supply chain | HIGH | Remote-update path using an unpinned package runner | CWE-829, GHSA-jxh8-jh77-xh6g |

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
- Automatic `npx`, `npm exec`, `pnpx`, `bunx`, `uvx`, `pipx run`, and package
  `dlx` calls in bundled scripts are reported when their package selector is
  mutable. Exact semantic versions, full commit identifiers, local paths,
  `--offline`, and `--no-install` are excluded. A higher-severity chain requires
  remote update control and installation mutation in the same executable file.
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
`DATASET/{benign,malicious}/CASE/SKILL.md` or flat Markdown cases under each
label directory:

```bash
waingro benchmark ./dataset --threshold suspicious
waingro benchmark ./dataset --format json --output benchmark.json \
  --fail-under-precision 0.95 --fail-under-recall 0.90 \
  --fail-under-average-precision 0.90
```

The report separates threshold classification from an intent-neutral review
ranking. `review_score` measures how urgently evidence should be investigated;
it is not a probability of malicious intent and cannot produce a `MALICIOUS`
verdict. Average precision and recall-at-budget show whether known malicious
controls actually rise to the top instead of rewarding raw alert volume.

On the 100-case [Runtime Skill Audit](https://github.com/tu-tuing/Runtime-Skill-Audit)
dataset at revision `559986985e38f3d8743a217b69e37cb258c9b566`, WAINGRO's
legacy static `SUSPICIOUS+` boundary produced 47 true positives, 0 false
positives, 50 true negatives, and 3 false negatives: 100% precision, 94%
recall, and 96.9% F1.
The three misses are narrative-only disclosures with no active instruction or
executable dataflow. This is one external dataset, not a claim of universal
performance; keep adding real malicious samples and adversarial benign controls.
The hybrid review ranking placed 47 of 50 malicious cases in the first 50
positions (94% recall) with 96.97% average precision; none of the 50 benign
cases received medium or high review priority.

On the 180 Claude-format cases in
[SkillFortifyBench](https://github.com/qualixar/skillfortifybench) revision
`eb9d5a9cbfa13b82ec3392d26dbae82fc6454b39`, the legacy static
`SUSPICIOUS+` boundary produced 58 true positives, 0 false positives, 90 true
negatives, and 32 false negatives: 100% precision, 64.4% recall, and 78.4% F1.
The broader alert boundary, including `WARNING`, detected 78 of 90 malicious
cases with no benign false positives.
The difference exposes intentional limits: credential collection without a
sink remains a warning, while typo- and dependency-squatting need an external
ecosystem baseline. Benchmark percentages describe these frozen datasets, not
the probability of detecting an unknown malicious skill.
The hybrid review ranking placed 78 of 90 malicious cases in the first 90
positions (86.67% recall) with 93.12% average precision; none of the 90 benign
cases received medium or high review priority.

### Fresh ClawHub validation

On 2026-09-11, revision `45c0d7a6538876197508ee8c2e9bf50a210690d9`
scanned a frozen, manifest-reconciled set of 79,840 current ClawHub skill
identities with zero scanner errors. The final distribution was 47,938 CLEAN,
3,089 WARNING, 5,797 REVIEW, 23,016 SUSPICIOUS, and 0 MALICIOUS. Rare critical
rules and an earlier pass's four top verdicts were manually reviewed; no
malicious publisher attribution was confirmed. Known poisoned controls still
reach `MALICIOUS`, so this is an honest negative with stated static-analysis
limits, not evidence that ClawHub is malware-free. See the
[full validation report](research/validation-2026-09-11.md).

WAINGRO 0.9.1 then re-scored the same frozen 79,840-artifact set at commit
`181cfebd545ba5fefcf1390d9d287961d6d61026` after tightening behavioral
mismatch and scoped-dataflow evidence and recovering declared purpose from
common malformed frontmatter. The final review ranking is 230 high, 11,405
medium, 17,824 low, and 50,381 with no review priority. Hybrid verdicts are
49,419 CLEAN, 27,223 CAPABILITY, 2,113 REVIEW, 1,085 SUSPICIOUS, and 0
MALICIOUS. High-priority volume fell 69.1% from the accepted 0.9.0 baseline of
744 while both external benchmark rankings remained unchanged. A bounded
50-item manual-review queue was produced with execution explicitly
unauthorized; no candidate was run. This is a re-score of the frozen corpus,
not a new acquisition, and a high review priority is not a malware attribution.
See the [high-risk refinement report](research/refinement-2026-09-12.md).

A subsequent provenance-first review re-verified all 50 queued artifact
identities. Twelve declared strong source claims were checked against public Git
history: 9 were corroborated, 1 was partially corroborated, and 2 declared
repositories were unavailable. No publisher was confirmed malicious. The pass
did identify one material dangerous-by-design architecture in
`clawgrid-connector`: a persistent agent accepts server-controlled instructions,
can auto-allow skill execution, and can act without owner-visible output. This
is a security finding, not a malware attribution. Dynamic execution remains
unauthorized; the follow-up shortlist is four exact artifacts, not the entire
high-priority cohort. See the
[provenance and dynamic-gate report](research/provenance-review-2026-09-12.md).

WAINGRO 0.10.0 generalizes that finding as `AGENT-001`. The rule requires four
facets within a bounded instruction span: remote instruction input, an authority
override, autonomous execution, and suppression of owner-visible output.
Persistence and automatic approval raise confidence but cannot produce a
malicious attribution. See the
[control-plane detection report](research/control-plane-detection-2026-09-12.md).

WAINGRO 0.11.0 implements the generic containment profile and non-authorizing
benign control catalog needed for the next safety gate. This is preparation,
not candidate evidence: hanna2 has been rebuilt as a dedicated Fedora Server 44
KVM host and its former data disk is physically disconnected. Candidate
execution remains blocked until the remaining firmware gate is complete and the
benign controls pass again afterward. Secure Boot is now enabled, while the
firmware-database update remains blocked on a firmware-console operation. See the
[containment readiness report](research/containment-readiness-2026-09-12.md).

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

- [September 2026 validation and fresh ClawHub scan](research/validation-2026-09-11.md)
  — 79,840 current skill identities plus independent positive and negative controls
- [September 2026 high-risk refinement](research/refinement-2026-09-12.md)
  — evidence corrections, manual dispositions, exact rescore, and unauthorized
  review queue
- [September 2026 provenance review](research/provenance-review-2026-09-12.md)
  — artifact-bound source corroboration, architectural findings, and a bounded
  unauthorized dynamic shortlist
- [September 2026 control-plane detection](research/control-plane-detection-2026-09-12.md)
  — generalized remote-authority detection and the fail-closed ClawGrid case
- [September 2026 containment readiness](research/containment-readiness-2026-09-12.md)
  — generic isolated-response controls, benign fixtures, and remaining hanna2 gates
- [September 2026 hanna2 control validation](research/hanna2-control-validation-2026-09-14.md)
  — dedicated-host hardening, KVM fixture results, fail-closed rejections, and remaining gates
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
- [npm npx documentation](https://docs.npmjs.com/cli/v12/commands/npx/)
- [GitHub Advisory GHSA-jxh8-jh77-xh6g](https://github.com/advisories/GHSA-jxh8-jh77-xh6g)

## License

MIT
