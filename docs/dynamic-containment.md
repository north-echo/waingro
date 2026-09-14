# Dynamic containment runbook

WAINGRO dynamic analysis is fail-closed. A static alert is not permission to
execute a skill, and a high-priority queue item is not evidence of malware.

## Phase 1: reversible preparation

1. Generate a maximum 50-item manual-review queue with `waingro dynamic
   prepare-campaign`. This command only reads scan results and candidate files.
2. Rank candidates with the intent-neutral `review_score`, then exclude
   possible embedded credentials, probable defensive tools, duplicate
   artifacts, repeated behavior families, candidates below both the selected
   path and review thresholds, and candidates without an explicit runnable
   entrypoint. A high review score is not an intent verdict.
3. Review every selected artifact manually. Record its declared purpose,
   provenance, exact entrypoint, arguments, required executables, expected
   events, negative control, and why runtime behavior is needed.
4. Record unresolved hypotheses in a non-executing case dossier. Validate it
   with `waingro dynamic check-case`; a case must keep every authorization gate
   false, select no entrypoint, bind inert fixtures by digest, require all
   controls, and remain not ready for execution.
5. Validate the digest-pinned benign catalog with `waingro dynamic
   check-controls deploy/hanna2/control-suite.json`. Catalog validation reads
   fixtures but does not create plans, transfer content, or execute anything.
6. Do not create an authorized corpus plan during Phase 1.

## Phase 2: preserve and dedicate hanna2

1. Back up hanna2 to physically separate storage. `backup-host.sh` creates a
   crash-consistent XFS dump from an LVM snapshot, boot archive, partition and
   LVM metadata, configuration inventories, SHA-256 manifest, and compressed
   stream validation. The destination must be disconnected before testing.
2. Test restoration onto spare storage before relying on the backup.
   `restore-drill.sh` verifies every backup digest, restores the root dump into
   a newly created 200 GiB temporary LV, checks pinned root files, extracts the
   boot archive, records a receipt on the backup disk, and removes only that
   uniquely named temporary LV. This tests the dump, not whether the host can
   boot from independently restored media.
3. Reinstall hanna2 from trusted media. Do not treat deletion of its existing
   VMs as a clean slate.
4. Back up any filesystem not covered by the root XFS snapshot separately.
   In particular, preserve and then physically disconnect hanna2's `/data`
   disk and the offline backup destination for the duration of the campaign.
5. Keep the machine free of personal data, cloud credentials, developer keys,
   package-manager credentials, unrelated workloads, containers, and remote
   desktop services.
6. Configure a management-only firewall path, apply all updates, then disable
   host egress for the campaign.
7. Install WAINGRO and run `prepare-host.sh`. The initial policy permits
   fixtures only and contains an empty corpus artifact allowlist. The script
   arms egress lockdown with a 120-second rollback. Reconnect through the
   management-only SSH rule and run `sudo waingro-egress-lockdown commit`;
   host posture remains untrusted until this per-boot commit succeeds. The
   rollback timer is also armed automatically at boot, so an uncommitted or
   management-breaking ruleset removes itself instead of becoming persistent.
   The policy and boot marker remain root-owned and non-writable by the runner,
   but are group-readable so the unprivileged preflight can validate them.

## Phase 3: containment validation

1. Confirm that `waingro dynamic preflight` passes as the dedicated
   `waingro-runner` account. Preflight must reject disabled or unreadable Secure
   Boot state, a world-accessible KVM device, missing IOMMU groups, or an
   uncommitted egress marker. Host provisioning must separately reject audit
   task suppression.
2. Run benign, positive, timeout, fork/resource, output-volume, DNS, HTTP, TLS,
   missing-executable, tampered-plan, tampered-image, and post-run posture
   controls.
3. Confirm every guest has no network interface other than loopback. The
   loopback sinkhole provides local DNS plus bounded HTTP and HTTPS telemetry,
   but no guest NIC and no route. A fixed response is served only for its
   digest-bound host, TLS SNI name, method, and path; all other routes return a
   fixed 404 response.
4. Confirm transient domains, overlays, ISO files, console logs, and candidate
   copies disappear after every control.
5. Confirm unsigned, incomplete, policy-unbound, or isolation-invalid traces
   cannot become trusted evidence.
6. For layout-sensitive fixtures, confirm the artifact appears only through a
   root-owned, read-only OpenClaw path. Confirm synthetic JSON is digest-bound,
   readable by the unprivileged guest user, and bind-mounted read-only.
7. For inert command controls, first confirm the base guest contains no real
   executable with the planned name. Only then install the root-owned no-op
   shim. An intercepted `openclaw cron` or `crontab` invocation must produce
   telemetry and no scheduling or agent side effect.
8. Confirm the explicit qcow2 backing-store source is marked non-relabelable in
   the libvirt XML. The writable overlay remains dynamically labeled, while the
   digest-pinned base image must remain root-owned and byte-identical after
   every guest.

The packaged control catalog remains explicitly unauthorized. Each guest
fixture needs its own separately reviewed fixture plan, exact entrypoint,
coverage requirements, pinned base-image and host-policy digests, and explicit
job confirmation before Phase 3 execution. Do not reuse those fixture gates for
a corpus artifact.

## Phase 4: separately authorized corpus campaign

1. Replace the fixture policy with a root-owned policy containing a new
   campaign ID, `corpus_execution_enabled: true`, and only the exact artifact
   SHA-256 values approved after manual review.
2. Restart the egress-lockdown service so its boot-scoped marker binds the new
   policy digest.
3. Create each plan with both `--authorize-execution` and
   `--authorize-corpus`. Confirm the exact job ID at execution time.
4. Run no more than ten specimens before checking host integrity, disk space,
   trace completeness, control behavior, and containment drift.
5. Stop immediately after any unexplained host change, unexpected interface,
   egress-lock failure, signature failure, resource breach, or cleanup failure.
   Preserve evidence without rendering candidate output and rebuild hanna2.

## Evidence and disclosure

Dynamic observation establishes behavior, not subjective intent or publisher
attribution. Require two pristine reproductions, a negative control, manual
source review, exact artifact identity, complete coverage, and provider/destination
context before describing behavior as malicious. Keep incident dossiers private.
WAINGRO never files reports or publishes findings; the operator handles any
coordinated disclosure.

Assisted by Claude Code
