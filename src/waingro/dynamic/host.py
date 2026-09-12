"""Fail-closed host policy and posture checks for dynamic analysis.

The execution host is part of the evidence boundary.  A valid guest trace is
not trusted when the host is shared, its egress lock is inactive, or the
runner is privileged through an administrative group.
"""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import socket
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

HOST_POLICY_SCHEMA = "1.0"
DEFAULT_HOST_POLICY = Path("/etc/waingro/host-policy.json")
DEFAULT_EGRESS_MARKER = Path("/run/waingro/egress-locked")
ALLOWED_NETWORK_POLICIES = frozenset({"none", "loopback-sinkhole"})
ALLOWED_SPECIMEN_CLASSES = frozenset({"fixture", "corpus"})
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_FORBIDDEN_GROUPS = frozenset({"docker", "podman", "wheel", "sudo", "lxd", "incus"})
_FORBIDDEN_SERVICES = (
    "docker.service",
    "containerd.service",
    "podman.service",
    "kubelet.service",
    "ollama.service",
    "tailscaled.service",
)


class HostPolicyError(RuntimeError):
    """The host policy or current host posture is unsafe."""


@dataclass(frozen=True)
class HostPolicy:
    host: str
    runner_user: str
    dedicated: bool
    corpus_execution_enabled: bool
    campaign_id: str
    allowed_artifact_sha256: tuple[str, ...]
    allowed_network_policies: tuple[str, ...]
    egress_marker: Path
    policy_sha256: str

    def authorizes(self, specimen_class: str, artifact_sha256: str, campaign_id: str) -> bool:
        if specimen_class == "fixture":
            return campaign_id == self.campaign_id
        return (
            specimen_class == "corpus"
            and self.corpus_execution_enabled
            and campaign_id == self.campaign_id
            and artifact_sha256 in self.allowed_artifact_sha256
        )


def _read_root_policy(path: Path) -> tuple[bytes, os.stat_result]:
    if path.is_symlink():
        raise HostPolicyError("host policy may not be a symlink")
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    if not stat.S_ISREG(info.st_mode):
        raise HostPolicyError("host policy is not a regular file")
    if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise HostPolicyError("host policy must be root-owned and not group/world writable")
    if info.st_size > 64 * 1024:
        raise HostPolicyError("host policy exceeds 64 KiB")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(resolved, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise HostPolicyError("host policy changed while opening")
        payload = os.read(descriptor, 64 * 1024 + 1)
    finally:
        os.close(descriptor)
    if len(payload) > 64 * 1024:
        raise HostPolicyError("host policy exceeds 64 KiB")
    return payload, info


def load_host_policy(path: Path = DEFAULT_HOST_POLICY) -> HostPolicy:
    payload, _info = _read_root_policy(path)
    try:
        raw = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HostPolicyError("host policy is not valid JSON") from exc
    if not isinstance(raw, dict) or raw.get("schema_version") != HOST_POLICY_SCHEMA:
        raise HostPolicyError("unsupported host policy schema")
    host = raw.get("host")
    runner_user = raw.get("runner_user")
    campaign_id = raw.get("campaign_id")
    allowed_digests = raw.get("allowed_artifact_sha256")
    allowed_network = raw.get("allowed_network_policies")
    egress_marker = raw.get("egress_marker")
    if host != "hanna2":
        raise HostPolicyError("host policy is not bound to hanna2")
    if not isinstance(runner_user, str) or not _NAME_RE.fullmatch(runner_user):
        raise HostPolicyError("host policy runner_user is invalid")
    if not isinstance(campaign_id, str) or not _NAME_RE.fullmatch(campaign_id):
        raise HostPolicyError("host policy campaign_id is invalid")
    if raw.get("dedicated") is not True:
        raise HostPolicyError("host policy does not declare a dedicated machine")
    if not isinstance(raw.get("corpus_execution_enabled"), bool):
        raise HostPolicyError("host policy corpus gate is invalid")
    if (
        not isinstance(allowed_digests, list)
        or len(allowed_digests) > 10_000
        or len(allowed_digests) != len(set(allowed_digests))
        or any(
            not isinstance(item, str) or not _DIGEST_RE.fullmatch(item)
            for item in allowed_digests
        )
    ):
        raise HostPolicyError("host policy artifact allowlist is invalid")
    if (
        not isinstance(allowed_network, list)
        or not allowed_network
        or len(allowed_network) != len(set(allowed_network))
        or any(item not in ALLOWED_NETWORK_POLICIES for item in allowed_network)
    ):
        raise HostPolicyError("host policy network allowlist is invalid")
    if not isinstance(egress_marker, str) or not egress_marker.startswith("/run/waingro/"):
        raise HostPolicyError("host policy egress marker is invalid")
    return HostPolicy(
        host=host,
        runner_user=runner_user,
        dedicated=True,
        corpus_execution_enabled=raw["corpus_execution_enabled"],
        campaign_id=campaign_id,
        allowed_artifact_sha256=tuple(allowed_digests),
        allowed_network_policies=tuple(allowed_network),
        egress_marker=Path(egress_marker),
        policy_sha256=hashlib.sha256(payload).hexdigest(),
    )


def _command(arguments: list[str], timeout: int = 10) -> subprocess.CompletedProcess[str]:
    executable = shutil.which(arguments[0])
    if executable is None:
        return subprocess.CompletedProcess(arguments, 127, "", "not installed")
    return subprocess.run(  # noqa: S603 -- fixed host inspection commands, never a shell.
        [executable, *arguments[1:]],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )


def _groups_for_user(user: str) -> set[str]:
    account = pwd.getpwnam(user)
    names = {grp.getgrgid(account.pw_gid).gr_name}
    for record in grp.getgrall():
        if user in record.gr_mem:
            names.add(record.gr_name)
    return names


def _secure_marker(path: Path, policy_sha256: str) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    info = path.stat()
    if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) or info.st_size > 4096:
        return False
    try:
        marker = json.loads(path.read_text(encoding="utf-8"))
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return bool(
        isinstance(marker, dict)
        and marker.get("schema_version") == "1.0"
        and marker.get("locked") is True
        and marker.get("policy_sha256") == policy_sha256
        and marker.get("boot_id") == boot_id
    )


def inspect_host_posture(
    policy_path: Path = DEFAULT_HOST_POLICY,
    *,
    work_root: Path | None = None,
) -> dict:
    """Return a bounded, read-only posture report.  All checks are fail-closed."""
    checks: dict[str, dict[str, object]] = {}
    try:
        policy = load_host_policy(policy_path)
    except (OSError, HostPolicyError) as exc:
        return {
            "schema_version": "1.0",
            "ready": False,
            "policy_sha256": None,
            "checks": {"host_policy": {"ok": False, "observed": str(exc)}},
        }

    hostname = socket.gethostname().split(".", 1)[0]
    user = pwd.getpwuid(os.geteuid()).pw_name
    groups = _groups_for_user(user)
    checks["hostname"] = {"ok": hostname == policy.host, "observed": hostname}
    checks["runner_user"] = {"ok": user == policy.runner_user, "observed": user}
    checks["unprivileged"] = {"ok": os.geteuid() != 0, "observed": os.geteuid()}
    elevated = sorted(groups & _FORBIDDEN_GROUPS)
    checks["no_admin_groups"] = {"ok": not elevated, "observed": elevated}

    kvm = Path("/dev/kvm")
    checks["kvm"] = {
        "ok": (
            kvm.exists()
            and stat.S_ISCHR(kvm.stat().st_mode)
            and os.access(kvm, os.R_OK | os.W_OK)
        ),
        "observed": str(kvm),
    }
    enforce = Path("/sys/fs/selinux/enforce")
    selinux = enforce.read_text(encoding="ascii").strip() if enforce.is_file() else None
    checks["selinux_enforcing"] = {"ok": selinux == "1", "observed": selinux}
    checks["egress_lock"] = {
        "ok": _secure_marker(policy.egress_marker, policy.policy_sha256),
        "observed": str(policy.egress_marker),
    }

    for command in ("virsh", "qemu-img", "xorriso", "ssh-keygen"):
        found = shutil.which(command)
        checks[command] = {"ok": found is not None, "observed": found}

    uri = _command(["virsh", "-c", "qemu:///system", "uri"])
    checks["libvirt_system"] = {
        "ok": uri.returncode == 0 and uri.stdout.strip() == "qemu:///system",
        "observed": (uri.stdout or uri.stderr).strip()[:1000],
    }
    domains = _command(["virsh", "-c", "qemu:///system", "list", "--all", "--name"])
    domain_names = sorted(item for item in domains.stdout.splitlines() if item)
    checks["dedicated_domains"] = {
        "ok": domains.returncode == 0 and not domain_names,
        "observed": domain_names,
    }
    networks = _command(["virsh", "-c", "qemu:///system", "net-list", "--name"])
    network_names = sorted(item for item in networks.stdout.splitlines() if item)
    checks["no_active_libvirt_networks"] = {
        "ok": networks.returncode == 0 and not network_names,
        "observed": network_names,
    }

    active_services = []
    for service in _FORBIDDEN_SERVICES:
        state = _command(["systemctl", "is-active", service])
        if state.returncode == 0 and state.stdout.strip() == "active":
            active_services.append(service)
    checks["no_forbidden_services"] = {"ok": not active_services, "observed": active_services}
    firewalld = _command(["systemctl", "is-active", "firewalld.service"])
    checks["firewalld"] = {
        "ok": firewalld.returncode == 0 and firewalld.stdout.strip() == "active",
        "observed": firewalld.stdout.strip() or firewalld.stderr.strip(),
    }
    default_zone = _command(["firewall-cmd", "--get-default-zone"])
    checks["default_drop_zone"] = {
        "ok": default_zone.returncode == 0 and default_zone.stdout.strip() == "drop",
        "observed": default_zone.stdout.strip() or default_zone.stderr.strip(),
    }

    if work_root is not None:
        safe = False
        observed = str(work_root)
        try:
            info = work_root.resolve(strict=True).stat()
            safe = (
                not work_root.is_symlink()
                and stat.S_ISDIR(info.st_mode)
                and info.st_uid == os.geteuid()
                and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            )
        except OSError as exc:
            observed = str(exc)
        checks["work_root"] = {"ok": safe, "observed": observed}

    return {
        "schema_version": "1.0",
        "ready": all(item["ok"] is True for item in checks.values()),
        "policy_sha256": policy.policy_sha256,
        "campaign_id": policy.campaign_id,
        "corpus_execution_enabled": policy.corpus_execution_enabled,
        "checks": checks,
    }


def require_host_posture(
    policy_path: Path,
    *,
    expected_policy_sha256: str,
    specimen_class: str,
    artifact_sha256: str,
    campaign_id: str,
    network_policy: str,
    work_root: Path,
) -> HostPolicy:
    policy = load_host_policy(policy_path)
    if policy.policy_sha256 != expected_policy_sha256:
        raise HostPolicyError("host policy digest does not match the authorized plan")
    if network_policy not in policy.allowed_network_policies:
        raise HostPolicyError("host policy does not permit the requested network policy")
    if not policy.authorizes(specimen_class, artifact_sha256, campaign_id):
        raise HostPolicyError("host policy does not authorize this specimen")
    posture = inspect_host_posture(policy_path, work_root=work_root)
    if not posture["ready"]:
        failed = sorted(name for name, item in posture["checks"].items() if not item["ok"])
        raise HostPolicyError("host posture failed: " + ", ".join(failed))
    return policy
