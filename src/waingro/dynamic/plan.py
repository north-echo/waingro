"""Generate fail-closed execution plans for the hanna2 KVM harness."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
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
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_INTERPRETER_EXECUTABLE = {"python": "python3", "node": "node", "shell": "bash"}
INERT_COMMAND_SHIMS = frozenset({"crontab", "openclaw"})
SYNTHETIC_VALUE_PROFILES = frozenset({"access-key", "api-key", "password", "secret-key", "token"})
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
MAX_EMBEDDED_JSON_BYTES = 64 * 1024
MAX_SYNTHETIC_JSON_FILES = 8


@dataclass(frozen=True)
class EmbeddedJsonFile:
    home_path: str
    sha256: str
    size_bytes: int
    body_base64: str

    def to_dict(self) -> dict:
        return {
            "home_path": self.home_path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "body_base64": self.body_base64,
        }


@dataclass(frozen=True)
class SinkholeHttpResponse:
    host: str
    method: str
    path: str
    sha256: str
    size_bytes: int
    body_base64: str

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "method": self.method,
            "path": self.path,
            "status": 200,
            "content_type": "application/json",
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "body_base64": self.body_base64,
        }


def _json_record(body: bytes, *, label: str) -> tuple[str, int, str]:
    if not isinstance(body, bytes) or not body or len(body) > MAX_EMBEDDED_JSON_BYTES:
        raise ValueError(f"{label} must contain 1 to {MAX_EMBEDDED_JSON_BYTES} bytes")
    try:
        decoded = body.decode("utf-8")
        parsed = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} must be valid UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} root must be a JSON object")
    return hashlib.sha256(body).hexdigest(), len(body), base64.b64encode(body).decode("ascii")


def read_embedded_json(path: Path) -> bytes:
    """Read one bounded, non-symlink JSON fixture for plan embedding."""
    absolute = path.absolute()
    resolved = path.resolve(strict=True)
    if absolute != resolved or path.is_symlink():
        raise ValueError("embedded JSON path must not traverse a symlink")
    info = resolved.stat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_EMBEDDED_JSON_BYTES:
        raise ValueError("embedded JSON fixture size or type violates policy")
    descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            info.st_dev,
            info.st_ino,
            info.st_size,
        ):
            raise ValueError("embedded JSON fixture changed while opening")
        chunks = []
        remaining = MAX_EMBEDDED_JSON_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        body = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(body) != info.st_size:
        raise ValueError("embedded JSON fixture changed while reading")
    _json_record(body, label="embedded JSON fixture")
    return body


def _home_json_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or ".." in path.parts
        or not 2 <= len(path.parts) <= 4
        or not path.parts[0].startswith(".")
        or path.parts[0] in {".aws", ".ssh"}
        or path.suffix.lower() != ".json"
        or any(not re.fullmatch(r"[A-Za-z0-9._-]+", part) for part in path.parts)
    ):
        raise ValueError("synthetic JSON home path violates policy")
    return value


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
    openclaw_skill_slug: str | None
    inert_command_shims: tuple[str, ...]
    sinkhole_http_response: SinkholeHttpResponse | None
    synthetic_json_files: tuple[EmbeddedJsonFile, ...]
    required_event_types: tuple[str, ...]
    require_exit_zero: bool
    created_at: str
    schema_version: str = "1.3"

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
                "containment": {
                    "openclaw_skill_slug": self.openclaw_skill_slug,
                    "inert_command_shims": list(self.inert_command_shims),
                    "sinkhole_http_response": (
                        self.sinkhole_http_response.to_dict()
                        if self.sinkhole_http_response
                        else None
                    ),
                    "synthetic_json_files": [item.to_dict() for item in self.synthetic_json_files],
                },
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
    material = {key: value for key, value in document.items() if key != "job_id"}
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
    openclaw_skill_slug: str | None = None,
    inert_command_shims: tuple[str, ...] = (),
    sinkhole_http_host: str | None = None,
    sinkhole_http_method: str | None = None,
    sinkhole_http_path: str | None = None,
    sinkhole_http_body: bytes | None = None,
    synthetic_json_files: tuple[tuple[str, bytes], ...] = (),
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
    containment_requested = bool(
        openclaw_skill_slug
        or inert_command_shims
        or sinkhole_http_host
        or sinkhole_http_method
        or sinkhole_http_path
        or sinkhole_http_body
        or synthetic_json_files
    )
    if containment_requested and interpreter is None:
        raise ValueError("a containment profile requires an explicit scenario")
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
    shims = tuple(inert_command_shims)
    if (
        len(shims) != len(set(shims))
        or any(item not in INERT_COMMAND_SHIMS for item in shims)
        or any(item in required_executables for item in shims)
    ):
        raise ValueError("inert command shims violate policy")
    if openclaw_skill_slug is not None and not _CAMPAIGN_RE.fullmatch(openclaw_skill_slug):
        raise ValueError("OpenClaw skill slug violates policy")
    sinkhole_values = (
        sinkhole_http_host,
        sinkhole_http_method,
        sinkhole_http_path,
        sinkhole_http_body,
    )
    if any(value is not None for value in sinkhole_values) and not all(
        value is not None for value in sinkhole_values
    ):
        raise ValueError("sinkhole HTTP response requires host, method, path, and JSON body")
    sinkhole_response = None
    if sinkhole_http_body is not None:
        if network_policy != "loopback-sinkhole":
            raise ValueError("sinkhole HTTP response requires loopback-sinkhole networking")
        if (
            not isinstance(sinkhole_http_host, str)
            or not isinstance(sinkhole_http_method, str)
            or not isinstance(sinkhole_http_path, str)
        ):
            raise ValueError("sinkhole HTTP response requires host, method, and path strings")
        if not _HOST_RE.fullmatch(sinkhole_http_host):
            raise ValueError("sinkhole HTTP host violates policy")
        if sinkhole_http_method not in {"GET", "POST"}:
            raise ValueError("sinkhole HTTP method violates policy")
        if (
            not sinkhole_http_path.startswith("/")
            or len(sinkhole_http_path) > 2048
            or any(
                ord(character) < 0x21 or ord(character) > 0x7E for character in sinkhole_http_path
            )
            or "#" in sinkhole_http_path
        ):
            raise ValueError("sinkhole HTTP path violates policy")
        response_digest, response_size, response_base64 = _json_record(
            sinkhole_http_body,
            label="sinkhole HTTP response",
        )
        sinkhole_response = SinkholeHttpResponse(
            host=sinkhole_http_host.lower(),
            method=sinkhole_http_method,
            path=sinkhole_http_path,
            sha256=response_digest,
            size_bytes=response_size,
            body_base64=response_base64,
        )
    if len(synthetic_json_files) > MAX_SYNTHETIC_JSON_FILES:
        raise ValueError("too many synthetic JSON files")
    embedded_json = []
    seen_home_paths: set[str] = set()
    for home_path, body in synthetic_json_files:
        normalized_path = _home_json_path(home_path)
        if normalized_path in seen_home_paths:
            raise ValueError("synthetic JSON home paths must be unique")
        seen_home_paths.add(normalized_path)
        file_digest, file_size, file_base64 = _json_record(
            body,
            label=f"synthetic JSON file {home_path}",
        )
        embedded_json.append(EmbeddedJsonFile(normalized_path, file_digest, file_size, file_base64))
    executables = tuple(required_executables)
    if interpreter is not None:
        executables = tuple(dict.fromkeys((*executables, _INTERPRETER_EXECUTABLE[interpreter])))
    if sinkhole_response is not None:
        executables = tuple(dict.fromkeys((*executables, "openssl")))
    if len(executables) > 32 or any(not _EXECUTABLE_RE.fullmatch(item) for item in executables):
        raise ValueError("required executables violate policy")
    environment = tuple(synthetic_environment)
    environment_names = [name for name, _profile in environment]
    if (
        len(environment) > 16
        or len(environment_names) != len(set(environment_names))
        or any(
            not synthetic_environment_name_allowed(name) or profile not in SYNTHETIC_VALUE_PROFILES
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
        openclaw_skill_slug=openclaw_skill_slug,
        inert_command_shims=shims,
        sinkhole_http_response=sinkhole_response,
        synthetic_json_files=tuple(embedded_json),
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
