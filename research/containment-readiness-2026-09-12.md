# WAINGRO 0.11.0 containment readiness

Author: Christopher Lusk, North Echo
Date: 2026-09-12
Updated: 2026-09-13

## Outcome

WAINGRO now has the generic guest-side primitives required to test an
architecture-sensitive skill without granting it live network access or real
agent and scheduler commands. This is an implementation and local verification
result, not runtime evidence about any ClawHub artifact.

No corpus candidate was imported, installed, transferred, or executed. No
candidate, publisher, dependency, report, or ClawHub endpoint was contacted.
No report was filed. Hanna2 was later accessed only for the preservation gate
described below; no control or candidate was executed.

## Implemented containment profile

Dynamic plan schema 1.3 binds these optional components into the job ID:

- A root-owned immutable alias from the guest's expected OpenClaw skill path to
  the exact read-only artifact copied from the input ISO.
- Up to eight bounded JSON objects embedded by digest and size, then exposed at
  constrained guest-home paths through read-only, `nosuid`, `nodev`, `noexec`
  bind mounts.
- Root-owned inert `openclaw` and `crontab` shims. The guest refuses the plan if
  either real executable is present before shim installation. Shims emit a
  fixed marker, return success, and perform no scheduling or agent action.
- A guest-only DNS and HTTP(S) sinkhole. The guest has no emulated network
  interface. A one-day guest-local CA is trusted only through candidate-process
  environment variables. The JSON response is served only when the TLS SNI,
  HTTP Host, method, and path match the plan; all response bytes are digest- and
  size-bound.
- Telemetry for exact sinkhole route matches and inert persistence-command
  interception. Existing process, file, credential, DNS, network, timeout,
  output, trace, overlay, and host-space limits remain active.

The plan builder validates these fields, the runner independently revalidates
them before boot, and the guest rechecks embedded JSON identities and real-shim
absence before starting a candidate.

## Benign control gate

The repository includes a 14-control catalog. Six benign guest artifacts are
digest-pinned: a file/process canary, a negative control, exact DNS/HTTPS
sinkhole response, inert shim interception, watchdog timeout, and output-volume
limit. Eight additional contracts cover resource-policy rejection, missing
executables, tampered plan and image rejection, trace-trust rejection,
before/after host posture, and transient-guest cleanup.

`waingro dynamic check-controls deploy/hanna2/control-suite.json` verifies the
catalog, every fixture identity, the mandatory control semantics, and that all
transfer and execution gates remain false. It creates no plan and executes no
fixture.

Evidence identities:

- Control suite SHA-256:
  `83eb263c5d06ae28b215bb1ccfe46f7331607e7f399fc7fc08ea7245cee49e9d`
- ClawGrid case SHA-256:
  `5d13e97058dc3dc6d6844d6b2fa5da2fa8a5c0165e7cd7d60bf257d6f8330310`
- ClawGrid heartbeat response SHA-256:
  `c946b9c2cbc06d0725f7c0aa46c7834cd1771db903d9aba60a6044c161fdfd64`
- ClawGrid synthetic configuration SHA-256:
  `a3fe0c6cbe1c2b9afc3ca85f59501b3489cb85e2fe0f048f7aaf63211d03db1b`

## Hanna2 preservation gate

On 2026-09-13, both the root NVMe and separate SATA `/data` device reported a
passing SMART health assessment with no reported media or data-integrity
errors. The root XFS filesystem was captured from a 32 GiB LVM snapshot to the
separate `/dev/sda` disk. The dump reported success after processing about 105
GiB, compressed to a 53 GiB archive. Both compressed streams and every entry in
the backup SHA-256 manifest verified before the output was promoted from its
`.partial` name.

An initial attempt failed closed before producing a usable root dump because
Fedora 43 requires stdout as a standalone `xfsdump` operand. Its snapshot and
mount were removed, the 430 MiB failure directory was retained, and the command
was corrected and covered by a static regression assertion before the
successful attempt.

The root dump SHA-256 is
`a708caa1dab4bc2ec8861fb8d6b23edd3e1d111669563490ddfcaf3ff0cc1d61`.
A restore drill then reverified the manifest, restored the root dump into a new
200 GiB temporary LV, matched three snapshot-pinned root-file hashes, extracted
the boot archive, and removed the temporary mount and LV. The restore receipt
SHA-256 is
`6391fb2e3d658e46779c41e2fc719c626b7c628121e52089c29afbcae51bfb79`.

Six ephemeral container attach sockets with overlong paths were discarded by
`xfsrestore`; it reported no regular-file restore error and completed with
success. The drill tests dump readability and selected file integrity. It does
not test bootability from independently restored media, and `/data` is the only
copy of its own pre-existing contents. The evidence summary is digest
`ae461d74f76d5807fa59333843616dee099e7f636fd356e0905746330d89f8cc`.

## Remaining gate

The benign catalog has not run on hanna2. Before any remote control execution,
the verified `/data` disk must be physically disconnected, hanna2 must receive
a trusted clean rebuild, and its base image and host policy must be frozen and
digest-pinned before complete benign-control receipts are collected. A future
post-campaign restore should use the preserved disk only after testing ends.

Only after those controls pass should a separate review consider selecting one
ClawGrid entrypoint. That review would still need to explicitly authorize host
policy, corpus transfer, corpus execution, and the exact job ID. Nothing in this
release opens those gates.

This work does not establish malicious intent, a campaign, country of origin,
government sponsorship, or publisher attribution.

Assisted by Claude Code
