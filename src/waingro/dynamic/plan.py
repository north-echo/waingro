"""Generate fail-closed execution plans for the hanna2 KVM harness."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from waingro.dynamic.host import (
    ALLOWED_NETWORK_POLICIES,
    ALLOWED_SPECIMEN_CLASSES,
    inspect_host_posture,
)
from waingro.models import ArtifactFileDigest, ArtifactIdentity

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.qcow2$")
_ENTRYPOINT_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?$")
_EXECUTABLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_ENVIRONMENT_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_CAMPAIGN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_INTERPRETER_EXECUTABLE = {"python": "python3", "node": "node", "shell": "bash"}
SYNTHETIC_VALUE_PROFILES = frozenset(
    {"access-key", "api-key", "password", "secret-key", "token"}
)
_RESERVED_ENVIRONMENT_NAMES = frozenset(
    {"BASH_ENV", "ENV", "HOME", "IFS", "PATH", "SHELL", "SHELLOPTS", "USER"}
)
_RESERVED_ENVIRONMENT_PREFIXES = ("LD_", "NODE_", "PYTHON", "WAINGRO_")
COVERAGE_EVENT_TYPES = frozenset(
    {"credential", "defense-evasion", "dns", "file", "network", "persistence", "process"}
)


def synthetic_environment_name_allowed(name: str) -> bool:
    return bool(
        _ENVIRONMENT_RE.fullmatch(name)
        and name not in _RESERVED_ENVIRONMENT_NAMES
        and not name.startswith(_RESERVED_ENVIRONMENT_PREFIXES)
    )


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
    host_policy_sha256: str
    campaign_id: str
    specimen_class: str
    corpus_authorized: bool
    network_policy: str
    timeout_seconds: int
    memory_mib: int
    vcpus: int
    execution_authorized: bool
    interpreter: str | None
    entrypoint: str | None
    arguments: tuple[str, ...]
    required_executables: tuple[str, ...]
    synthetic_environment: tuple[tuple[str, str], ...]
    required_event_types: tuple[str, ...]
    require_exit_zero: bool
    created_at: str
    schema_version: str = "1.2"

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
                "host_policy_sha256": self.host_policy_sha256,
                "campaign_id": self.campaign_id,
                "specimen_class": self.specimen_class,
                "corpus_authorized": self.corpus_authorized,
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
                        "required_executables": list(self.required_executables),
                        "synthetic_environment": {
                            name: profile for name, profile in self.synthetic_environment
                        },
                        "coverage": {
                            "required_event_types": list(self.required_event_types),
                            "require_exit_zero": self.require_exit_zero,
                        },
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
    host_policy_sha256: str | None = None,
    campaign_id: str = "fixture-validation",
    specimen_class: str = "fixture",
    authorize_corpus: bool = False,
    network_policy: str = "none",
    timeout_seconds: int = 120,
    memory_mib: int = 1024,
    vcpus: int = 1,
    authorize_execution: bool = False,
    interpreter: str | None = None,
    entrypoint: str | None = None,
    arguments: tuple[str, ...] = (),
    required_executables: tuple[str, ...] = (),
    synthetic_environment: tuple[tuple[str, str], ...] = (),
    required_event_types: tuple[str, ...] = (),
    require_exit_zero: bool = False,
) -> DynamicPlan:
    _validate_artifact(artifact)
    digest = base_image_sha256.lower()
    if not _DIGEST_RE.fullmatch(digest):
        raise ValueError("base image SHA-256 must be 64 hexadecimal characters")
    policy_digest = (host_policy_sha256 or "0" * 64).lower()
    if not _DIGEST_RE.fullmatch(policy_digest):
        raise ValueError("host policy SHA-256 must be 64 hexadecimal characters")
    if authorize_execution and policy_digest == "0" * 64:
        raise ValueError("authorized execution requires a pinned host policy digest")
    if not _CAMPAIGN_RE.fullmatch(campaign_id):
        raise ValueError("campaign ID violates policy")
    if specimen_class not in ALLOWED_SPECIMEN_CLASSES:
        raise ValueError("specimen class must be fixture or corpus")
    if specimen_class == "corpus" and authorize_execution and not authorize_corpus:
        raise ValueError("corpus execution requires separate explicit authorization")
    if specimen_class == "fixture" and authorize_corpus:
        raise ValueError("fixture plans may not carry corpus authorization")
    if network_policy not in ALLOWED_NETWORK_POLICIES:
        raise ValueError("network policy must be none or loopback-sinkhole")
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
    if authorize_execution and not required_event_types:
        raise ValueError("authorized execution requires at least one coverage event")
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
    if len(required_executables) != len(set(required_executables)):
        raise ValueError("required executables violate policy")
    executables = tuple(required_executables)
    if interpreter is not None:
        executables = tuple(dict.fromkeys((*executables, _INTERPRETER_EXECUTABLE[interpreter])))
    if (
        len(executables) > 32
        or any(not _EXECUTABLE_RE.fullmatch(item) for item in executables)
    ):
        raise ValueError("required executables violate policy")
    environment = tuple(synthetic_environment)
    environment_names = [name for name, _profile in environment]
    if (
        len(environment) > 16
        or len(environment_names) != len(set(environment_names))
        or any(
            not synthetic_environment_name_allowed(name)
            or profile not in SYNTHETIC_VALUE_PROFILES
            for name, profile in environment
        )
    ):
        raise ValueError("synthetic environment configuration violates policy")
    coverage_events = tuple(dict.fromkeys(required_event_types))
    if (
        len(coverage_events) > len(COVERAGE_EVENT_TYPES)
        or len(coverage_events) != len(required_event_types)
        or any(item not in COVERAGE_EVENT_TYPES for item in coverage_events)
    ):
        raise ValueError("coverage event requirements violate policy")
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
        host_policy_sha256=policy_digest,
        campaign_id=campaign_id,
        specimen_class=specimen_class,
        corpus_authorized=authorize_corpus,
        network_policy=network_policy,
        timeout_seconds=timeout_seconds,
        memory_mib=memory_mib,
        vcpus=vcpus,
        execution_authorized=authorize_execution,
        interpreter=interpreter,
        entrypoint=entrypoint,
        arguments=tuple(arguments),
        required_executables=executables,
        synthetic_environment=environment,
        required_event_types=coverage_events,
        require_exit_zero=require_exit_zero,
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


def preflight_hanna2(policy_path: Path | None = None, work_root: Path | None = None) -> dict:
    """Read-only dedicated-host checks.  This function never starts a VM."""
    if policy_path is None:
        return inspect_host_posture(work_root=work_root)
    return inspect_host_posture(policy_path, work_root=work_root)
