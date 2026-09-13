# WAINGRO 0.10.0 control-plane detection

Author: Christopher Lusk, North Echo
Date: 2026-09-12

## Outcome

WAINGRO now detects a dangerous agent control-plane pattern that its earlier
primitive-centered rules did not express: a remote service supplies
instructions, those instructions are elevated over local control, execution is
automatic, and the result is hidden from the owner. The new `AGENT-001` rule
found one such chain in the frozen 79,840-artifact ClawHub corpus, in the exact
`clawgrid-connector` artifact already selected for architectural review.

This is a capability finding. It does not establish malicious intent, a
campaign, a government sponsor, a country of origin, or publisher attribution.
Names, language, hosting geography, and superficial infrastructure associations
would not be sufficient attribution evidence.

No candidate was imported, installed, transferred, or executed. No dependency,
candidate endpoint, report endpoint, publisher, or ClawHub reporting action was
contacted. Hanna2 was not accessed or modified.

## Detection model

`AGENT-001` requires all four of these facets within an 80-line root-manifest
window:

1. A remote server, service, platform, publisher, heartbeat, webhook, or API
   response supplies an instruction-like payload.
2. The payload is assigned precedence or required authority.
3. The agent is directed to execute or proceed automatically.
4. Owner-visible output or notification is suppressed.

Automatic approval and scheduled persistence raise confidence only after all
four required facets exist. They cannot independently create the finding. The
rule excludes protective instructions and emits a SHA-256 digest of the bounded
evidence excerpt for later comparison. Its behavior-graph path is represented
as command-and-control to execution and mapped to ATT&CK T1071 and T1059 as
behavioral references, not attribution claims.

## Precision refinement

The rule was measured against the same frozen path manifest after each
structural revision. No publisher-specific or slug-specific suppression was
added.

- Initial pass: three hits, zero scanner errors. Besides `clawgrid-connector`,
  two Alibaba Cloud operational skills were false positives. The matcher had
  treated the phrase "API command" as proof that an instruction came from a
  remote authority, then joined unrelated human-in-the-loop and truncation
  guidance.
- Second pass: two hits, zero scanner errors. The Alibaba cases were removed by
  requiring a remote entity to deliver an instruction. An Antom reconciliation
  skill still joined "command not found," repository download guidance, a
  generic "must follow" phrase, and silent error handling.
- Final pass: one hit, zero scanner errors. Requiring an explicit relationship
  between the instruction and a named remote source removed the Antom join and
  retained the ClawGrid chain.

The final measurement covered 79,840 paths. Its frozen path-manifest SHA-256 is
`4e822f6fb20d69c5881bf32a8fda2c51bf80c6dc58794b8a91516a5ffc52b366`.
The retained finding occurs at line 294, has high severity and 0.95 confidence,
and spans 64 lines. It includes both approval-weakening and persistence
amplifiers. The exact scanned artifact SHA-256 is
`fe043bf2f62c0193ff4619149b7952abdee6b208551b81c6ca38ab407f7c24c1`.

Adversarial tests cover the positive four-facet chain, owner-confirmed remote
tasks, local silent scheduling, high-priority remote alerts without execution,
defensive guidance, out-of-window facets, and the repository-download/silent-
error false-positive construction.

The two independent labeled controls were also re-run in hybrid-static mode.
Their established rankings did not move:

- Runtime Skill Audit: 100 cases, zero errors, 96.97% average precision,
  94% recall at the 50-positive review cutoff, and 25 true positives with zero
  false positives at `SUSPICIOUS+`.
- SkillFortifyBench Claude split: 180 cases, zero errors, 93.12% average
  precision, 86.67% recall at the 90-positive review cutoff, and 16 true
  positives with zero false positives at `SUSPICIOUS+`.

These controls demonstrate that precision refinement did not suppress the
known positive signal. They do not estimate the probability of detecting an
unknown malicious skill.

## Non-executing Hanna2 case

The repository now contains a pre-execution dossier for that exact artifact.
It is deliberately incapable of authorizing a run:

- Execution, corpus, and candidate-transfer gates are all false.
- No entrypoint is selected; three observed entrypoints are proposals marked
  `execute: false`.
- The expected host is exactly `hanna2` with libvirt/KVM, an ephemeral overlay,
  no host shares or credentials, no external guest interface or live egress, a
  read-only ISO transport, and a loopback sinkhole policy.
- The synthetic heartbeat fixture is JSON-only and digest-pinned.
- Benign-canary, negative-control, before/after posture, and guest-destruction
  controls are mandatory.
- Unresolved blockers must remain present, so successful validation always
  reports `ready_for_execution: false`.
- Case, fixture, and candidate paths may not traverse symlinks. When a candidate
  is supplied, WAINGRO statically re-scans it, requires the exact artifact
  digest, and verifies each proposed entrypoint belongs to that artifact.

Evidence identities:

- Case SHA-256:
  `26bf61ca0d215683f544358d32742cfda51de59d081ef15112262381a4783bea`
- Synthetic heartbeat fixture SHA-256:
  `c946b9c2cbc06d0725f7c0aa46c7834cd1771db903d9aba60a6044c161fdfd64`
- Synthetic configuration fixture SHA-256:
  `a3fe0c6cbe1c2b9afc3ca85f59501b3489cb85e2fe0f048f7aaf63211d03db1b`

The generic loopback response, OpenClaw layout, synthetic JSON, and inert shim
components were subsequently implemented and locally unit-tested in WAINGRO
0.11.0. The dossier remains blocked because the benign suite has not run on
hanna2, the base image has not proved that real shim targets are absent, and the
backup, restore, rebuild, and containment-control sequence has not been
recorded complete.

## Interpretation and next gate

The result is interesting because it describes a server-directed autonomy
architecture that ordinary shell, network, and persistence primitives do not
capture as a whole. It is not proof that the remote service ever returned a
harmful task. Static text establishes the client-side authority path but cannot
observe server behavior, conditional activation, or operator intent.

The next safe step is to preserve and rebuild hanna2, freeze the base image and
host policy, then run the independently digest-pinned benign controls. Any
proposal to transfer or execute the corpus artifact still requires a separate
review and explicit authorization after that restoration and containment
evidence is complete.

Assisted by Claude Code
