# WAINGRO 0.9.1 high-risk refinement

Author: Christopher Lusk, North Echo  
Date: 2026-09-12

## Outcome

No current ClawHub skill has been confirmed malicious. This pass refined the
remaining high-risk review cohort; it did not relabel those candidates as
malware or treat finding volume as success.

The analysis was read-only. No candidate was imported, installed, or executed.
No dependency, candidate endpoint, semantic API, report endpoint, publisher, or
ClawHub reporting action was contacted. Hanna2 was not modified.

## Corrections made

- `BEHAV-001` now requires payment or subscription mutation syntax instead of
  matching status prose such as `refunded`.
- `BEHAV-002` now requires a concrete bulk target, a bounded confirmation-bypass
  phrase, or a genuinely external sensitive-data destination. API method
  catalogs, ambiguous `clear all` prose, ordinary API-key authentication, and
  protective confirmation requirements no longer become attack-shaped evidence.
  Declared management/lifecycle purposes cover their expected mutations, and a
  skipped approval paired with explicit non-execution is not a bypass.
- Purpose declarations can come from the root title and first prose paragraph
  when frontmatter is absent.
- Malformed YAML frontmatter receives conservative recovery of only standard,
  unindented, single-line identity fields. This preserves declared purpose for
  common unquoted-colon descriptions without guessing nested metadata or block
  values.
- `EXFIL-008` now requires the sensitive source to reach a local-read primitive.
  A nearby `.env` mention or existence check is not treated as transmitted data.
- Lexical dataflow stops at blank and control-flow boundaries after a multiline
  statement opener, preventing a sink in one function from joining a source in
  another.

These changes correct evidence construction. They do not weaken the
artifact-bound gate required for a `MALICIOUS` verdict.

## Independent benchmark controls

Both datasets were read statically and never executed. Retrieval is unchanged
from the accepted 0.9.0 baseline.

### Runtime Skill Audit

- Dataset revision: `559986985e38f3d8743a217b69e37cb258c9b566`
- Cases: 50 malicious, 50 benign
- Average precision: 96.97%
- Top-50 retrieval: 47 malicious, 3 benign; 94% malicious recall
- Hybrid `SUSPICIOUS+`: 25 true positives, 0 false positives

### SkillFortifyBench Claude split

- Dataset revision: `eb9d5a9cbfa13b82ec3392d26dbae82fc6454b39`
- Cases: 90 malicious, 90 benign
- Average precision: 93.12%
- Top-90 retrieval: 78 malicious, 12 benign; 86.67% malicious recall
- Hybrid `SUSPICIOUS+`: 16 true positives, 0 false positives

These labeled controls establish that the refinement did not merely suppress
all alerts. They do not estimate detection probability for an unknown sample.

## Frozen ClawHub rescore

- Scanner commit: `181cfebd545ba5fefcf1390d9d287961d6d61026`
- Frozen path manifest: 79,840 artifacts
- Manifest SHA-256:
  `4e822f6fb20d69c5881bf32a8fda2c51bf80c6dc58794b8a91516a5ffc52b366`
- Scanner errors: 0
- Hybrid verdicts: 49,419 CLEAN; 27,223 CAPABILITY; 2,113 REVIEW;
  1,085 SUSPICIOUS; 0 MALICIOUS
- Review priorities: 230 high; 11,405 medium; 17,824 low; 50,381 none
- Dynamic priorities: 230 high; 9,033 medium; 70,577 none
- Candidates marked `dynamic_recommended`: 230
- High-cohort verdicts: 161 CAPABILITY; 69 SUSPICIOUS; 0 MALICIOUS
- Bounded manual-review queue: 50 high-priority entries selected from 141
  eligible runnable artifacts; every entry has `execution_authorized: false`

The prior 0.9.0 baseline contained 744 high-priority rows. The final reduction
to 230 is 69.1%. It is useful only because benchmark retrieval stayed fixed and
the removed rows were traced to identifiable evidence defects. Sixteen rows
moved from medium to high because they explicitly document confirmation-bypass
capabilities; no unexplained promotion remained. The final high cohort is a
review queue, not a count of malicious skills.

## Manual evidence refinement

### `x402-cli`

Disposition: dangerous by design, but no evidence of covert or malicious intent.

The skill prominently discloses autonomous Base USDC spending, lack of an
in-tool confirmation gate, private-key exposure risk, use of a dedicated
low-value wallet, and a per-invocation spend limit. The observed capability
matches its purpose. Arbitrary service URLs and the missing human gate remain
material operational risks. An unresolved `x402ClientSync` annotation also
appears to be a quality defect, not malicious evidence.

### `spaces`

Disposition: purpose-aligned remote service client; endpoint provenance remains
the relevant unresolved question.

The code sends the Moltspaces credential to the declared Moltspaces service and
uses OpenAI and ElevenLabs credentials through the corresponding SDKs. The
service URL is configurable and the skill warns that changing it can redirect
credentials. No covert credential destination or unrelated local-data transfer
was found. Public source copies support benign use, but do not establish
original authorship or endpoint ownership.

### `telegram-colored-choices-buttons`

Disposition: false positive removed.

The repeated word `destructive` describes Telegram button styling for dangerous
choices; it is not an instruction to perform those actions. The only outbound
destination in the inspected client is the declared Telegram Bot API. Local
`.env` references are credential setup primitives, not evidence of exfiltration.

### `prompt-guard`

Disposition: defensive example corpus, moved from high/SUSPICIOUS to
medium/REVIEW after metadata recovery.

Its invalid YAML caused the parser to discard the explicit prompt-injection
guard description and security tags. The apparent malicious instructions are
attack examples paired with refusal and detection guidance.

### `evolver` and `capability-evolver`

Disposition: unresolved supply-chain risk, not confirmed malicious.

Both variants contain a disclosed self-update path that invokes an unpinned
`degit` package through `npx`, installs a remotely selected version, and restarts
the tool. The repository version tag is pinned, but the package runner is not.
That is a real update-chain risk and remains suitable for provenance-first
review. Disclosure and purpose alignment argue against treating it as covert
behavior without artifact history or runtime evidence.

## Interpretation and next gate

High review priority means that static evidence warrants analyst time. It is
not a malicious classification. The remaining cohort is dominated by
purpose-aligned privileged tools: wallets, trading, deployment, tunnels,
storage, messaging, secret handling, and social posting.

Any later dynamic work must start from an exact artifact digest and a manually
approved entrypoint. It must use a disposable KVM guest with no host mounts,
clipboard, shared folders, live credentials, LAN route, or unrestricted egress;
all execution remains unauthorized until those gates are independently met.
This pass creates no basis for reporting a skill or attributing a publisher.

## Evidence hashes

- Exact-code hybrid JSONL:
  `34ac20ea12726c47080fff3e98fc639fd24293a1b93c489b5fd250b67d98b1c0`
- Exact-code summary:
  `f2a334dfae4cb76275f3a6c953314a3731a767367dab25fc5d651ce46d67267f`
- Unauthorized manual-review queue:
  `d75493d2bbf75d83694085925be4cb574f693b23996c4bbbe182ca7eb414447e`
- Runtime Skill Audit benchmark:
  `133ce08e367b4abd8589bf5fb1be4a35ad736739d56ba4e6d16f5b2be11a053a`
- SkillFortifyBench benchmark:
  `97ac00400d1169d323d58e82f2cc8ac529d40a2d04a7bc208388c9c6e228c48f`

Assisted by Claude Code
