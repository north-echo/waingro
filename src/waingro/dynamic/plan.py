"""Generate fail-closed execution plans for the hanna2 KVM harness."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import stat
import subprocess
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from waingro.models import ArtifactFileDigest, ArtifactIdentity

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.qcow2$")
_ENTRYPOINT_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?$")
MAX_ARTIFACT_FILES = 10_000
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024


def _validate_artifact(artifact: ArtifactIdentity) -> None:
    if (
        artifact.algorithm != "sha256"
        or not _DIGEST_RE.fullmatch(artifact.sha256)
        or artifact.file_count != len(artifact.files)
        or not 1 <= artifact.file_count <= MAX_ARTIFACT_FILES
        or not 0 <= artifact.total_bytes <= MAX_ARTIFACT_BYTES
    ):
        raise ValueError("artifact identity violates dynamic analysis policy")
    scope_digest = hashlib.sha256()
    total = 0
    paths = []
    for item in sorted(artifact.files, key=lambda record: record.path):
        relative = PurePosixPath(item.path)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or len(relative.parts) > 2
            or not _DIGEST_RE.fullmatch(item.sha256)
            or not 0 <= item.size_bytes <= MAX_ARTIFACT_BYTES
        ):
            raise ValueError("artifact file record violates dynamic analysis policy")
        path_bytes = item.path.encode("utf-8")
        scope_digest.update(len(path_bytes).to_bytes(8, "big"))
        scope_digest.update(path_bytes)
        scope_digest.update(item.size_bytes.to_bytes(8, "big"))
        scope_digest.update(bytes.fromhex(item.sha256))
        total += item.size_bytes
        paths.append(item.path)
    if (
        len(paths) != len(set(paths))
        or total != artifact.total_bytes
        or scope_digest.hexdigest() != artifact.sha256
    ):
        raise ValueError("artifact file inventory does not match its identity")


@dataclass(frozen=True)
class DynamicPlan:
    job_id: str
    artifact_sha256: str
    artifact_file_count: int
    artifact_total_bytes: int
    artifact_files: tuple[ArtifactFileDigest, ...]
    expected_host: str
    backend: str
    base_image: str
    base_image_sha256: str
    network_policy: str
    timeout_seconds: int
    memory_mib: int
    vcpus: int
    execution_authorized: bool
    interpreter: str | None
    entrypoint: str | None
    arguments: tuple[str, ...]
    created_at: str
    schema_version: str = "1.0"

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "job_id": self.job_id,
            "artifact": {
                "sha256": self.artifact_sha256,
                "file_count": self.artifact_file_count,
                "total_bytes": self.artifact_total_bytes,
                "files": [
                    {
                        "path": item.path,
                        "sha256": item.sha256,
                        "size_bytes": item.size_bytes,
                    }
                    for item in self.artifact_files
                ],
            },
            "execution": {
                "authorized": self.execution_authorized,
                "expected_host": self.expected_host,
                "backend": self.backend,
                "base_image": self.base_image,
                "base_image_sha256": self.base_image_sha256,
                "disk_mode": "ephemeral-overlay",
                "candidate_transport": "read-only-iso",
                "host_shares": False,
                "host_credentials": False,
                "synthetic_credentials": True,
                "network_policy": self.network_policy,
                "timeout_seconds": self.timeout_seconds,
                "memory_mib": self.memory_mib,
                "vcpus": self.vcpus,
                "scenario": (
                    {
                        "interpreter": self.interpreter,
                        "entrypoint": self.entrypoint,
                        "arguments": list(self.arguments),
                    }
                    if self.interpreter and self.entrypoint
                    else None
                ),
            },
            "telemetry": {
                "processes": True,
                "file_access": True,
                "persistence": True,
                "dns": True,
                "network": True,
                "credential_canaries": True,
            },
            "created_at": self.created_at,
        }


def dynamic_job_id(document: dict) -> str:
    """Bind a confirmation ID to every field in a serialized execution plan."""
    material = {
        key: value
        for key, value in document.items()
        if key != "job_id"
    }
    canonical = json.dumps(
        material,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"waingro-{hashlib.sha256(canonical).hexdigest()[:20]}"


def build_dynamic_plan(
    artifact: ArtifactIdentity,
    *,
    base_image: str,
    base_image_sha256: str,
    network_policy: str = "none",
    timeout_seconds: int = 120,
    memory_mib: int = 1024,
    vcpus: int = 1,
    authorize_execution: bool = False,
    interpreter: str | None = None,
    entrypoint: str | None = None,
    arguments: tuple[str, ...] = (),
) -> DynamicPlan:
    _validate_artifact(artifact)
    digest = base_image_sha256.lower()
    if not _DIGEST_RE.fullmatch(digest):
        raise ValueError("base image SHA-256 must be 64 hexadecimal characters")
    if network_policy != "none":
        raise ValueError("dynamic execution currently requires network policy none")
    if not 10 <= timeout_seconds <= 300:
        raise ValueError("dynamic timeout must be between 10 and 300 seconds")
    if not 256 <= memory_mib <= 2048:
        raise ValueError("dynamic memory must be between 256 and 2048 MiB")
    if vcpus != 1:
        raise ValueError("dynamic analysis is restricted to one vCPU")
    if (interpreter is None) != (entrypoint is None):
        raise ValueError("interpreter and entrypoint must be provided together")
    if authorize_execution and (interpreter is None or entrypoint is None):
        raise ValueError("authorized execution requires an explicit scenario")
    if interpreter is not None and interpreter not in {"python", "node", "shell"}:
        raise ValueError("scenario interpreter must be python, node, or shell")
    if entrypoint is not None:
        entry_path = PurePosixPath(entrypoint)
        if (
            entry_path.is_absolute()
            or ".." in entry_path.parts
            or len(entry_path.parts) > 2
            or not entry_path.parts
            or not _ENTRYPOINT_RE.fullmatch(entrypoint)
        ):
            raise ValueError("scenario entrypoint must be a relative path at depth two or less")
        allowed_suffixes = {
            "python": {".py"},
            "node": {".js", ".mjs", ".cjs"},
            "shell": {".sh"},
        }
        if entry_path.suffix.lower() not in allowed_suffixes[interpreter]:
            raise ValueError("scenario entrypoint suffix does not match its interpreter")
        if entrypoint not in {item.path for item in artifact.files}:
            raise ValueError("scenario entrypoint is not in the scanned artifact")
    if len(arguments) > 32 or any(
        len(argument) > 1024 or "\0" in argument for argument in arguments
    ):
        raise ValueError("scenario arguments exceed policy limits")
    base_name = Path(base_image).name
    if (
        not base_name
        or base_name in {".", ".."}
        or base_image != base_name
        or not _IMAGE_RE.fullmatch(base_name)
    ):
        raise ValueError("base image must be a qcow2 file name without a path")
    stamp = datetime.now(UTC).isoformat()
    provisional = DynamicPlan(
        job_id="",
        artifact_sha256=artifact.sha256,
        artifact_file_count=artifact.file_count,
        artifact_total_bytes=artifact.total_bytes,
        artifact_files=tuple(artifact.files),
        expected_host="hanna2",
        backend="libvirt-kvm",
        base_image=base_name,
        base_image_sha256=digest,
        network_policy=network_policy,
        timeout_seconds=timeout_seconds,
        memory_mib=memory_mib,
        vcpus=vcpus,
        execution_authorized=authorize_execution,
        interpreter=interpreter,
        entrypoint=entrypoint,
        arguments=tuple(arguments),
        created_at=stamp,
    )
    return replace(provisional, job_id=dynamic_job_id(provisional.to_dict()))


def write_plan(plan: DynamicPlan, output: Path) -> None:
    """Create a plan without overwriting an existing authorization record."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(output, flags, 0o600)
    try:
        payload = (json.dumps(plan.to_dict(), indent=2) + "\n").encode()
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def preflight_hanna2() -> dict:
    """Read-only host checks. This function never starts a VM."""
    checks: dict[str, dict] = {}
    hostname = socket.gethostname().split(".", 1)[0]
    checks["hostname"] = {"ok": hostname == "hanna2", "observed": hostname}
    checks["unprivileged_user"] = {"ok": os.geteuid() != 0, "observed": os.geteuid()}
    kvm = Path("/dev/kvm")
    kvm_ok = False
    if kvm.exists():
        mode = kvm.stat().st_mode
        kvm_ok = stat.S_ISCHR(mode) and os.access(kvm, os.R_OK | os.W_OK)
    checks["kvm"] = {"ok": kvm_ok, "observed": str(kvm)}
    for command in ("virsh", "qemu-img", "ssh-keygen"):
        found = shutil.which(command)
        checks[command] = {"ok": found is not None, "observed": found}
    enforce = Path("/sys/fs/selinux/enforce")
    selinux = enforce.read_text(encoding="ascii").strip() if enforce.is_file() else None
    checks["selinux_enforcing"] = {"ok": selinux == "1", "observed": selinux}
    virsh = shutil.which("virsh")
    if virsh:
        result = subprocess.run(  # noqa: S603 -- fixed command and no candidate input.
            [virsh, "-c", "qemu:///system", "uri"],
            capture_output=True,
            timeout=10,
            check=False,
            text=True,
            env={"PATH": "/usr/bin:/bin"},
        )
        checks["libvirt_system"] = {
            "ok": result.returncode == 0 and result.stdout.strip() == "qemu:///system",
            "observed": result.stdout.strip() or result.stderr.strip()[:300],
        }
    else:
        checks["libvirt_system"] = {"ok": False, "observed": None}
    return {
        "host": hostname,
        "ready": all(check["ok"] for check in checks.values()),
        "checks": checks,
    }
