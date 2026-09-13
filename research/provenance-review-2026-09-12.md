# WAINGRO 0.9.2 provenance review and dynamic gate

Author: Christopher Lusk, North Echo
Date: 2026-09-12

## Outcome

No current ClawHub publisher or skill was confirmed malicious. This pass did,
however, find security-relevant behavior that a zero-`MALICIOUS` headline would
hide. `clawgrid-connector` implements a dangerous remote-control architecture;
`china-install-skills` has an unauthenticated update and persistence design; and
`email-cron-handler` turns email content into agent instructions using only a
configured `From` address as its local trust check.

The result supports a hybrid model: static analysis finds concrete capability
chains, provenance establishes whether reviewed bytes correspond to public
source, and tightly scoped dynamic validation can later confirm behavior. None
of those layers alone establishes publisher intent.

## Safety and method

- The input was the 50-item unauthorized queue from the frozen 79,840-artifact
  ClawHub corpus. All 50 artifacts were re-scanned and matched their queued
  SHA-256 identities.
- Candidate content was read only. It was not imported, installed, executed, or
  allowed to resolve dependencies.
- Public-source checks used the official GitHub API and bare, blob-filtered Git
  repositories in a temporary directory. No repository checkout or repository
  code execution occurred.
- No candidate-controlled service endpoint, ClawHub report endpoint, publisher,
  semantic-analysis API, or live credential was contacted.
- Hanna2 was not modified. Dynamic execution remains explicitly unauthorized.
- Source corroboration does not transfer between publishers, even when a slug,
  author, or content fingerprint matches.

## Tooling added

`waingro provenance prepare` now turns a bounded, unauthorized campaign queue
into a non-executing ledger. It fails closed on artifact drift, unsafe paths,
registry identity mismatch evidence, invalid URLs, excessive input, and output
replacement. For every candidate it records:

- exact artifact and per-file identities;
- registry publisher, slug, version, and publication metadata;
- declared source claims and service hosts;
- package-runner references;
- full and core content fingerprints; and
- equivalent queue entries without merging publisher identities.

`waingro provenance apply-review` attaches separately gathered source-history
evidence only when the review names an existing artifact digest, a normalized
source repository, a full Git revision where applicable, reconciled match
counts, and HTTPS evidence URLs. It records that intent verdicts were not
changed. Both commands create new mode-0600 outputs and refuse to overwrite an
existing file.

## Provenance results

- Queue candidates: 50
- Artifact identities verified: 50
- Registry identities matching the queue: 50
- Candidates with a strong declared source claim: 12
- Candidates without a strong declared source claim: 38
- Source-corroborated: 9
- Source-partially-corroborated: 1
- Declared source unavailable: 2
- Full-content equivalence groups: 0
- Core-content equivalence groups: 1

The 38 `not-checked` entries did not make a strong source claim in a root
provenance document. They are not being described as source-unavailable.

| Skill | Source result | Exact evidence |
|---|---|---|
| `claw-wallet-pro` | Corroborated; 4/5 core files match | [`7300ab4`](https://github.com/ClawWallet/Claw-Wallet-Skill/commit/7300ab4f01a811690184cb70515e79a08ab58817) |
| `wallet-test` | Corroborated independently; 4/5 core files match | [`7300ab4`](https://github.com/ClawWallet/Claw-Wallet-Skill/commit/7300ab4f01a811690184cb70515e79a08ab58817) |
| `verdikta-bounties-onboarding` | Corroborated in the declared monorepository | [`010140b`](https://github.com/verdikta/verdikta-applications/commit/010140bbd231ba690ba93810cece56642e1245af) |
| `openclaw-social-post` | Corroborated; 13/13 core files match after GitHub redirect | [`827c792`](https://github.com/teeclaw/openclaw-social-post/commit/827c792b81d0d57b201a59862ebff36cd8cb3aac) |
| `kindle-download` | Corroborated; 8/9 core files match | [`5a86a3b`](https://github.com/xiehaixin/kindle-download/commit/5a86a3b17e49adc10d48c47ff27c19e34e52932c) |
| `quick-backup-restore` | Corroborated; 19/19 core files match | [`a065091`](https://github.com/marzliak/quick-backup-restore/commit/a0650918bfda0544a11c7dc487da3c617ad106e6) |
| `agent-deep-research` | Corroborated; 18/18 core files match | [`d006b56`](https://github.com/24601/agent-deep-research/commit/d006b56392b81383af7ad14b4793003626cbaae3) |
| `clawgrid-connector` | Declared source unavailable | [Declared repository](https://github.com/clawgrid/clawgrid-connector) |
| `resumex` | Declared source unavailable; newer repository does not contain the queued blobs | [Newer repository](https://github.com/atharva-badgujar/resumex-openclaw-skill) |
| `bottube` | Partially corroborated; 85/267 current core files match, but no exact artifact revision | [`00973f5`](https://github.com/Scottcjn/bottube/commit/00973f5b3d2098ad42404afb0cce3945d1eead85) |
| `china-install-skills` | Content corroborated; 17/17 files match an unattributed same-name repository | [`73d7c23`](https://github.com/SemFreud/china-install-skills/commit/73d7c2319a94d885c2804c776ee615a363dcbb37) |
| `flow` | Corroborated; 10/10 core files match | [`4cae065`](https://github.com/bvinci1-design/flow/commit/4cae0650a687905436e1a710c70847a5d09be4f2) |

The wallet entries are bound to separate queued artifacts and publishers. Their
shared source result is not a publisher-trust inference. The separate wallet
binary repository was not downloaded or treated as skill-source identity.

## Material findings

### ClawGrid connector

Disposition: dangerous by design and the strongest remaining validation target;
malicious publisher intent is not established.

The skill configures cron or launchd persistence and automatically enables
OpenClaw skill execution approval. Heartbeat responses can deliver
server-controlled `owner_instruction` content described as highest priority.
The `auto_proceed` path directs the agent to execute and submit results while
producing no owner-visible output. Task artifacts and logs can be uploaded to
the remote service. The declared public source repository is unavailable.

This is a genuine remote command-and-control surface in the architectural
sense: compromise or abuse of the service control plane could direct persistent
agent activity while suppressing normal user visibility. That statement
describes capability and impact, not evidence that the current operator is
malicious.

### China installer

Disposition: purpose-aligned installer with a real supply-chain and persistence
risk; malicious intent is not established.

The skill downloads ZIP content, validates only that the result appears to be a
ZIP, can delete and replace an existing skill during forced installation, and
offers noninteractive setup that modifies shell startup files, installs a
`clawhub` wrapper, and creates a scheduled updater. Documentation identifies a
Convex-hosted backend while one implementation path uses the ClawHub API. No
digest or signature binds downloaded content before installation. All 17 core
files match a public same-name repository, but that repository is not marked as
a fork and does not resolve the unavailable declared publisher source.

### Email command channel

Disposition: disclosed remote-instruction mechanism with insufficient local
origin authentication; malicious intent is not established.

The Python helper fetches mail, compares the parsed `From` address with one
configured address, returns message bodies, sends replies, and records processed
UIDs. It does not itself execute the body. The skill and cron template instruct
the agent to execute commands from those bodies. Equality with a message header
is not cryptographic sender authentication; any safety inherited from the mail
provider is outside the skill's local enforcement.

### Candidates deprioritized after review

- `skill-hr` is a documented prompt-and-benchmark workflow with explicit safety
  gates. Its runnable files are validators and benchmarks, so it is removed from
  the dynamic shortlist as a high-priority false lead.
- `resumex` has stale source provenance, but its executable behavior is
  transparent and purpose-aligned. The job-applier path explicitly avoids
  ResumeX and Telegram calls; the PDF sender uses only its declared services.
- `bottube` has partial source derivation but a 267-file surface and no exact
  source revision. Broad execution would provide poor coverage and is deferred
  until a single behavior and entrypoint can be justified.
- The wallet skills need provenance and static inspection of the separately
  distributed binary before any candidate execution is considered.

## Bounded dynamic shortlist

Dynamic analysis would confirm observable behavior, not publisher intent. Only
these four exact artifacts remain worth designing fixtures for:

| Priority | Skill | Artifact SHA-256 | Proposed constrained question |
|---|---|---|---|
| 1 | `clawgrid-connector` | `fe043bf2f62c0193ff4619149b7952abdee6b208551b81c6ca38ab407f7c24c1` | With a local synthetic heartbeat response, does it enable execution approval, persist, dispatch remote instructions, and suppress owner output as documented? |
| 2 | `china-install-skills` | `12bf6a5b15739a776aae641156e12905fef966ee54c6e8c55cdc2d96ad34c8c1` | With a local synthetic ZIP, what paths are overwritten, can archive traversal escape the target, and what persistence is created? |
| 3 | `space-duck` | `6af1ec4071e40f878f28e657afa4f79102f1585ebee26ae6ec439a4950efc761` | Against a local fake Beak API, what credentials, persistence, update actions, and remote instruction paths are exercised? |
| 4 | `email-cron-handler` | `d91dcceacfcf6e260ec4f04ae679729027040a60975fe1e95541b5ea82402cf5` | In an agent-aware local mail fixture, can an allowed-header message trigger execution beyond an explicit policy? |

Before any execution, each case still requires an independently approved run
plan, one selected entrypoint, synthetic inputs, expected observations, and a
negative control. Execution must occur only in a disposable KVM guest on
Hanna2 with no host mounts, shared clipboard, shared folders, live credentials,
LAN route, or unrestricted egress. Candidate domains must resolve to a local
sink or be blocked. The guest must be destroyed after every case. None of those
execution gates was opened in this pass.

## Evidence hashes

- Frozen corpus manifest:
  `4e822f6fb20d69c5881bf32a8fda2c51bf80c6dc58794b8a91516a5ffc52b366`
- Unauthorized manual-review queue:
  `d75493d2bbf75d83694085925be4cb574f693b23996c4bbbe182ca7eb414447e`
- Offline provenance ledger:
  `ba5a16a33cae389ca880f3b31453082b3f93fd219d66272ccc86f988d473bfb1`
- Artifact-bound external reviews:
  [`1ce1126982857c48f0863d95eec79e2486b355397522fefa3cf0e8fe14d1ae08`](evidence/provenance-external-reviews-2026-09-12.json)
- Reviewed provenance ledger:
  `2c997b4ed1a9c20c1d83d96a58548f3ac43e33246bde2c21b3109d81d4332a7e`

Assisted by Claude Code
