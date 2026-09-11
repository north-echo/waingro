# WAINGRO validation and fresh ClawHub scan — 2026-09-11

Prepared for Christopher Lusk / North Echo Security Research  
Contact: clusk@northecho.dev

## Outcome

WAINGRO revision `45c0d7a6538876197508ee8c2e9bf50a210690d9` was
validated against two independent labeled datasets, known poisoned skills, and
a frozen set of 79,840 current ClawHub skill identities. The live-corpus scan
completed with `0` scanner errors and produced the following triage
distribution:

| Verdict | Count |
|---|---:|
| CLEAN | 47,938 |
| WARNING | 3,089 |
| REVIEW | 5,797 |
| SUSPICIOUS | 23,016 |
| MALICIOUS | 0 |

An immediately preceding fixed-set pass produced four `MALICIOUS` triage rows.
All four were manually adjudicated as defensive examples, and their shared
Markdown-section defect received a regression before the final pass. Confirmed
malicious skills in the fresh corpus: **0**. This is an honest corpus result, not a
claim that the ecosystem is malware-free. Static analysis cannot observe
server-side behavior, conditional activation, delayed downloads, or every
cross-function dataflow.

## Corpus and reproducibility

Acquisition was manifest-driven and reconciled by publisher/slug identity and
top-level path. It did not infer completeness from pagination headers.

| Item | Count |
|---|---:|
| Registry manifest rows | 78,187 |
| Unique manifest slugs | 78,163 |
| Unique top-level skill paths scanned | 79,840 |
| Acquired packages without a top-level `SKILL.md` | 63 |
| Unavailable manifest slugs | 22 |

- Frozen path-manifest SHA-256:
  `4e822f6fb20d69c5881bf32a8fda2c51bf80c6dc58794b8a91516a5ffc52b366`
- Final JSONL SHA-256:
  `e1b160373759290a356200e7fb02e3d8251e9868357839c9416f80144045a470`
- Scanner revision: `45c0d7a6538876197508ee8c2e9bf50a210690d9`
- Scan depth: root manifest plus supported bundled files no more than two
  directory levels below the skill root
- Scan errors: `0`

The 22 unavailable slugs remain an upstream coverage gap. No result was inferred
for them.

## Corpus adjudication

The pre-fix top bucket contained four defensive tools:

- `skill-security-auditor` quoted known infrastructure and shell-pipe patterns
  in threat descriptions and sample audit output.
- `mcp-security-audit` placed decode and execution examples under “Immediate
  Rejection” and “Needs Review.”
- `deepsafe-scan` listed reverse-shell, DNS-exfiltration, and persistence
  examples under its hooks scanner documentation.
- `skill-security-reviewer` carried encoded and hex-decoded commands under an
  obfuscation-detection examples hierarchy.

The shared error was structural: several clearly defensive headings were
classified as unknown or usage, and a numbered child example containing the
word “Commands” failed to inherit its detection parent. The corrected parser
uses section hierarchy and explicit defensive heading semantics. It does not
reduce confidence merely because a skill has a defensive name.

The final pass's rarest critical primitives were also inspected:

- The sole download-write-execute chain was a blocked example in SlowMist's
  supply-chain pattern reference.
- The sole DNS-exfiltration chain was a detector example in DeepSafe's hooks
  scanner documentation.
- The sole hex-decode execution hit was an example in Skill Security Reviewer's
  detection hierarchy.
- The sole metadata override phrase was quoted by Guardian Wall's defensive
  description and sanitizer rules.
- Encoded-execution and known-infrastructure hits were dominated by detection
  examples, fixtures, and IOC collections. None established an active malicious
  instruction chain outside that context.
- Machine-obfuscated bundles remain `SUSPICIOUS` where static inspection cannot
  safely establish intent. They were not converted into malicious publisher
  claims on opacity alone.

The corpus also contains real security and privacy review leads—cleartext
credential transport, external plaintext WebSockets, machine-identity uploads,
and mutable remote bootstraps—but those behaviors do not by themselves prove
malicious publisher intent.

## Independent benchmark results

### Runtime Skill Audit

The 100-case [Runtime Skill Audit](https://github.com/tu-tuing/Runtime-Skill-Audit)
dataset was tested at revision
`559986985e38f3d8743a217b69e37cb258c9b566`.

At the operational `SUSPICIOUS+` threshold:

| Measure | Result |
|---|---:|
| True positives | 47 / 50 |
| False positives | 0 / 50 |
| Precision | 100% |
| Recall | 94% |
| Specificity | 100% |
| F1 | 96.9% |

Result JSON SHA-256:
`b88a28304827c68cde08afbe5c7326d19ac0d6b3becfbc94c42bd5e291a0b454`.

The three misses contain narrative disclosures but no active instruction or
executable dataflow: an attacker email in a contact-lookup description, a
public-IP lookup transparently logged to a local/private endpoint, and an
offsite-backup email mentioned in a ping-check description.

### SkillFortifyBench

The 180 Claude-format cases in
[SkillFortifyBench](https://github.com/qualixar/skillfortifybench) were adapted
without altering their content and tested at revision
`eb9d5a9cbfa13b82ec3392d26dbae82fc6454b39`.

At `SUSPICIOUS+`, WAINGRO detected 58 of 90 malicious cases and produced no
false positives among 90 benign cases: 100% precision, 64.4% recall, and 78.4%
F1. At the broader alert boundary, which includes `WARNING`, it detected 78 of
90 malicious cases with no benign false positives: 100% precision and 86.7%
recall.

Result JSON SHA-256:
`f6e7cf3064bd183ca65d8c79d0b5beebd66f13f8b6dde02a7a4c0480b9e44099`.

The `SUSPICIOUS+` misses are informative rather than hidden. They consist of
credential collection without an outbound sink, steganographic or encoded
flows that remain warnings because their synthetic destinations use reserved
placeholder domains, and typo/dependency-squatting cases that require an
external ecosystem baseline. WAINGRO does not promote those primitives to an
intent verdict without the missing evidence.

These datasets measure detection on their samples; neither percentage is the
probability that WAINGRO will find an unknown malicious skill in ClawHub.

## Poisoned-skill controls

WAINGRO was also run against
[Snyk ToxicSkills](https://github.com/snyk-labs/toxicskills-goof) revision
`80ce2e06f52fd384163c4bd6778676019723773c` and a preserved known malicious
`twitter-sum` sample.

- The direct ClawHub poison and `twitter-sum` both reached `MALICIOUS` through
  exact decode-to-execution evidence plus an opaque password-protected remote
  executable. WAINGRO decoded the payload to a shell that retrieves bytes from
  `91.92.242.30`.
- Off-purpose system-information uploads, mutable remote instructions, hidden
  Unicode instructions, and credential-to-network flows reached
  `SUSPICIOUS` in the relevant ToxicSkills variants.
- Snyk's deliberately poisoned scanner-like skill remained `SUSPICIOUS` despite
  defensive metadata because its hidden active `curl | bash` instruction was
  not in a passive rule, fixture, or test context.
- The genuine Skill Defender signature collection was routed to `REVIEW` based
  on the location and structure of the evidence, not its claimed identity.

## Changes made from the evidence

- Added a non-executing `waingro benchmark` command with confusion matrices,
  precision, recall, specificity, F1, threshold gates, and per-case evidence.
- Replaced severity-as-intent aggregation with evidence-chain verdicts.
  `MALICIOUS` now requires direct DNS exfiltration or corroborating same-file
  evidence such as encoded execution or known infrastructure plus execution.
- Added bounded source-to-sink analysis for sensitive files, environment
  values, machine identity, remote downloads, decoded values, and execution or
  network sinks.
- Added coverage for password-protected executables, mutable remote
  instructions, download-write-execute chains, audit-log destruction,
  hidden-Unicode tag payloads, privileged world-writable paths, and off-purpose
  prerequisite transfers.
- Expanded bundled-file parsing to relevant shell, PowerShell, Python,
  JavaScript, TypeScript, Markdown, text, JSON, TOML, and YAML files while
  enforcing the two-level scan boundary.
- Limited defensive-context reductions to exact structural evidence: passive
  test/evaluation paths, actual detection sections, rule/example literals, and
  static signature collections. A defensive-looking name never lowers
  confidence.
- Added regression tests for malformed URLs, aliases, multiline flows, quoted
  instructions, Markdown code, defensive fixtures, multilingual sections, and
  poisoned tools that claim a defensive purpose.

## Interpretation

The fresh corpus did not yield a confirmed malicious publisher attribution.
The positive controls show that this result is not caused by a scanner that
cannot recognize known poisoned behavior. The labeled benchmarks also show that
WAINGRO should be operated at `SUSPICIOUS+`, not by counting only the deliberately
conservative `MALICIOUS` verdict.

The remaining blind spots are material: semantic deception without executable
behavior, multi-stage remote content, steganography, ecosystem-level package or
skill impersonation, and runtime-only activation. Those require registry
reputation, remote-artifact retrieval in a sandbox, semantic review, or dynamic
analysis rather than additional keyword regexes.

No ClawHub report endpoint was called and no finding was filed or published.

Assisted by Claude Code
