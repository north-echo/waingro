# Hanna2 dynamic-containment validation

Date: 2026-09-14

## Outcome

WAINGRO's 14-control containment suite passed on the dedicated `hanna2` KVM
host. The result validates the current harness and its fail-closed gates; it is
not evidence about any ClawHub skill and does not authorize corpus execution.
No corpus artifact was transferred to or executed on hanna2.

## Final host baseline

- Fedora Server 44, kernel `7.2.5-200.fc44.x86_64`.
- Secure Boot was enabled and verified after the initial suite. Preflight now
  reads the UEFI variable directly and fails closed when it is disabled,
  malformed, duplicated, or unavailable.
- SELinux enforcing; IOMMU enabled with 11 groups; `/dev/kvm` is
  `root:kvm 0660`.
- Key-only, source-restricted SSH with TCP, agent, stream-local, X11, and tunnel
  forwarding disabled.
- Firewalld default-drop inbound policy and boot-bound, policy-bound host egress
  lockdown. The lockdown uses a 120-second rollback and is trusted only after a
  successful management reconnect and explicit per-boot commit.
- Separate `nodev,nosuid,noexec` work and image filesystems. The prior data and
  backup disk remained physically disconnected.
- Base image SHA-256:
  `579d6307bf6748b4d315e29d7c2bbd664b2d6beb8da51bdc23ffe126a63829bf`.
  It remained `root:root 0444` and byte-identical after the final control runs.
- Fixture host-policy SHA-256:
  `add0178d41c870b6c0e9178e370c072db34eebbc13601363863733956a001bbc`.
  Corpus execution is false and its artifact allowlist is empty.
- Audit syscall suppression was removed; the final audit status recorded zero
  lost events. AIDE initialized 95,232 entries and immediately reported no
  differences.

## Control results

| Control | Expected | Observed |
|---|---|---|
| Host posture before | posture match | ready, no failed checks |
| Benign canary | `exit-0` | `exit-0`, 3 events, complete coverage |
| Negative control | `exit-0` | `exit-0`, 2 events, complete coverage |
| DNS/HTTPS sinkhole | `exit-0` | `exit-0`, 15 events, complete coverage |
| Inert command interception | `exit-0` | `exit-0`, 11 events, complete coverage |
| Timeout | `timeout` | guest-enforced `timeout` at 10 seconds |
| Output volume | `resource-limit` | guest-enforced output resource limit |
| Resource policy | reject | invalid memory rejected before VM creation |
| Missing executable | reject | absent base capability rejected before VM creation |
| Tampered plan | reject | job-identity mismatch rejected before VM creation |
| Tampered image | reject | base-image digest mismatch rejected before VM creation |
| Trace trust | reject tamper | pristine signature trusted; modified trace rejected |
| Host posture after | posture match | ready, no failed checks |
| Guest destruction | cleanup complete | no domains or transient job directories remained |

Every final guest trace recorded an empty external-interface list, no host
shares, a read-only candidate, and an ephemeral overlay. Timeout and
output-volume traces intentionally report incomplete behavioral coverage
because execution was truncated by the control being tested.

## Defects found and corrected during validation

- The original host egress chain ran before conntrack and could suppress SSH
  replies. It now runs after conntrack and activation uses an automatic
  rollback/reconnect/commit transaction on every boot.
- Libvirt inventory failures could be hidden by a shell pipeline. Provisioning
  now fails explicitly when either inventory query fails.
- The runner could not read the root-owned policy and boot marker. Both remain
  root-owned and non-writable but are group-readable by `waingro-runner`.
- Fedora's default KVM device mode was `0666`, and its default audit rules
  suppressed syscall auditing. Provisioning now applies `0660` and rejects the
  suppression rule.
- Libvirt's SELinux and DAC security drivers changed ownership of an implicit
  qcow2 backing file. The domain XML now declares the backing store explicitly
  and disables relabeling for both drivers; the writable overlay remains
  dynamically labeled, using libvirt's documented
  [per-source security-label override](https://libvirt.org/formatdomain.html#security-label).
- Fedora's `nss-resolve` bypassed the guest-local resolver. Sinkhole guests now
  use direct `files dns` resolution against `127.0.0.1`, and the synthetic CA
  is traversable without exposing its private key.

## September 14 maintenance follow-up

- The EFI System Partition was archived twice before firmware maintenance; both
  archives have separate SHA-256 manifests on hanna2.
- Lenovo accepted and applied the Secure Boot setting remotely. Hanna2 rebooted
  successfully through Fedora's signed shim, and `mokutil` reports Secure Boot
  enabled.
- Fresh trusted LVFS metadata identified high-urgency KEK, UEFI CA, and dbx
  updates. Two attempts to stage the Lenovo-signed KEK payload failed before
  flashing because firmware rejected the authenticated EFI-variable write.
  SELinux recorded no denial, and default-deny host egress was restored after
  each bounded maintenance window.

## Remaining hard gates

- Apply the pending UEFI key and revocation-database updates from Lenovo
  firmware setup; do not disable SELinux or bypass authenticated-variable
  protections to force the runtime update.
- Repeat the full control suite after that firmware-console operation.
- Keep the corpus policy disabled and the allowlist empty until a separate,
  artifact-specific campaign authorization is reviewed.
- Before any corpus run, repeat the full benign suite after the firmware and
  Secure Boot changes.

Assisted by Claude Code
