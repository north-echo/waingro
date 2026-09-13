# WAINGRO 0.11.0 containment readiness

Author: Christopher Lusk, North Echo
Date: 2026-09-12

## Outcome

WAINGRO now has the generic guest-side primitives required to test an
architecture-sensitive skill without granting it live network access or real
agent and scheduler commands. This is an implementation and local verification
result, not runtime evidence about any ClawHub artifact.

No corpus candidate was imported, installed, transferred, or executed. No
candidate, publisher, dependency, report, or ClawHub endpoint was contacted.
No report was filed. Hanna2 was not accessed or modified.

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
  `1a0df3bc2d67acfda95770657212d06bacbd2de47d6c4dd2c926dd3f19b189df`
- ClawGrid case SHA-256:
  `26bf61ca0d215683f544358d32742cfda51de59d081ef15112262381a4783bea`
- ClawGrid heartbeat response SHA-256:
  `c946b9c2cbc06d0725f7c0aa46c7834cd1771db903d9aba60a6044c161fdfd64`
- ClawGrid synthetic configuration SHA-256:
  `a3fe0c6cbe1c2b9afc3ca85f59501b3489cb85e2fe0f048f7aaf63211d03db1b`

## Remaining gate

The benign catalog has not run on hanna2. Before any remote control execution,
the machine still needs physically separate offline backup media, a successful
spare-disk restore drill, a trusted clean rebuild, a frozen and digest-pinned
base image and host policy, and complete benign-control receipts. The offline
backup and `/data` media must be physically disconnected during testing.

Only after those controls pass should a separate review consider selecting one
ClawGrid entrypoint. That review would still need to explicitly authorize host
policy, corpus transfer, corpus execution, and the exact job ID. Nothing in this
release opens those gates.

This work does not establish malicious intent, a campaign, country of origin,
government sponsorship, or publisher attribution.

Assisted by Claude Code
