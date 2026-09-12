"""Load and authenticate bounded runtime traces from the VM harness."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

from waingro.dynamic.models import (
    IsolationRecord,
    RuntimeCoverage,
    RuntimeEvent,
    RuntimeEventType,
    RuntimeTrace,
)

MAX_TRACE_BYTES = 20 * 1024 * 1024
MAX_EVENTS = 100_000
MAX_FIELD_LENGTH = 4096
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class RuntimeTraceError(ValueError):
    """A runtime trace is malformed, mismatched, or unauthenticated."""


def _regular_file(path: Path, max_bytes: int) -> bytes:
    if path.is_symlink():
        raise RuntimeTraceError(f"symlinks are not accepted: {path}")
    path = path.resolve(strict=True)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeTraceError(f"not a regular file: {path}")
    if info.st_size > max_bytes:
        raise RuntimeTraceError(f"file exceeds {max_bytes} bytes: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            info.st_dev,
            info.st_ino,
        ):
            raise RuntimeTraceError(f"file changed while opening: {path}")
        chunks = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(payload) > max_bytes:
        raise RuntimeTraceError(f"file exceeds {max_bytes} bytes: {path}")
    return payload


def verify_trace_signature(
    payload: bytes,
    signature_path: Path,
    allowed_signers: Path,
    *,
    identity: str = "hanna2",
) -> bool:
    """Verify an OpenSSH signature over the exact trace bytes."""
    signature = _regular_file(signature_path, 1024 * 1024)
    signers = _regular_file(allowed_signers, 1024 * 1024)
    executable = shutil.which("ssh-keygen")
    if executable is None:
        raise RuntimeTraceError("ssh-keygen is required to verify runtime receipts")
    # Verify immutable private copies so replacing either caller-owned file
    # after validation cannot change what ssh-keygen consumes.
    with tempfile.TemporaryDirectory(prefix="waingro-trace-verify-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        signature_copy = root / "trace.sig"
        signers_copy = root / "allowed_signers"
        signature_copy.write_bytes(signature)
        signers_copy.write_bytes(signers)
        signature_copy.chmod(0o600)
        signers_copy.chmod(0o600)
        completed = subprocess.run(  # noqa: S603 -- fixed executable and argument structure.
            [
                executable,
                "-Y",
                "verify",
                "-f",
                str(signers_copy),
                "-I",
                identity,
                "-n",
                "waingro-runtime-v1",
                "-s",
                str(signature_copy),
            ],
            input=payload,
            capture_output=True,
            timeout=10,
            check=False,
            env={"PATH": "/usr/bin:/bin"},
        )
    return completed.returncode == 0


def _text(value: object, field: str, *, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value or len(value) > MAX_FIELD_LENGTH:
        raise RuntimeTraceError(f"invalid runtime trace field: {field}")
    return value


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise RuntimeTraceError(f"invalid runtime trace field: {field}")
    return value


def _string_list(value: object, field: str, *, maximum: int = 32) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum:
        raise RuntimeTraceError(f"invalid runtime trace field: {field}")
    parsed = tuple(_text(item, field, required=True) or "" for item in value)
    if len(parsed) != len(set(parsed)):
        raise RuntimeTraceError(f"invalid runtime trace field: {field}")
    return parsed


def _digest(value: object, field: str) -> str:
    text = _text(value, field, required=True)
    if text is None:  # Defensive narrowing; required=True rejects this above.
        raise RuntimeTraceError(f"missing SHA-256 field: {field}")
    text = text.lower()
    if not _DIGEST_RE.fullmatch(text):
        raise RuntimeTraceError(f"invalid SHA-256 field: {field}")
    return text


def _event(raw: object, index: int) -> RuntimeEvent:
    if not isinstance(raw, dict):
        raise RuntimeTraceError(f"event {index} is not an object")
    try:
        event_type = RuntimeEventType(raw.get("type"))
    except ValueError as exc:
        raise RuntimeTraceError(f"event {index} has an unknown type") from exc
    process_id = raw.get("process_id")
    parent_id = raw.get("parent_process_id")
    if process_id is not None and (not isinstance(process_id, int) or process_id < 0):
        raise RuntimeTraceError(f"event {index} has an invalid process_id")
    if parent_id is not None and (not isinstance(parent_id, int) or parent_id < 0):
        raise RuntimeTraceError(f"event {index} has an invalid parent_process_id")
    labels = raw.get("labels", [])
    if not isinstance(labels, list) or len(labels) > 32:
        raise RuntimeTraceError(f"event {index} has invalid labels")
    parsed_labels = tuple(
        _text(label, f"events[{index}].labels", required=True) or "" for label in labels
    )
    success = raw.get("success")
    if success is not None and not isinstance(success, bool):
        raise RuntimeTraceError(f"event {index} has invalid success")
    timestamp = _text(
        raw.get("timestamp"), f"events[{index}].timestamp", required=True
    ) or ""
    _timestamp(timestamp, f"events[{index}].timestamp")
    return RuntimeEvent(
        event_type=event_type,
        action=_text(raw.get("action"), f"events[{index}].action", required=True) or "",
        timestamp=timestamp,
        process_id=process_id,
        parent_process_id=parent_id,
        process=_text(raw.get("process"), f"events[{index}].process"),
        target=_text(raw.get("target"), f"events[{index}].target"),
        destination=_text(raw.get("destination"), f"events[{index}].destination"),
        command=_text(raw.get("command"), f"events[{index}].command"),
        success=success,
        labels=parsed_labels,
    )


def _event_types(value: object, field: str) -> tuple[RuntimeEventType, ...]:
    if not isinstance(value, list) or len(value) > len(RuntimeEventType):
        raise RuntimeTraceError(f"invalid runtime trace field: {field}")
    try:
        parsed = tuple(RuntimeEventType(item) for item in value)
    except (TypeError, ValueError) as exc:
        raise RuntimeTraceError(f"invalid runtime trace field: {field}") from exc
    if RuntimeEventType.HARNESS in parsed or len(parsed) != len(set(parsed)):
        raise RuntimeTraceError(f"invalid runtime trace field: {field}")
    return parsed


def _coverage(
    raw: object,
    events: tuple[RuntimeEvent, ...],
    exit_status: str,
) -> RuntimeCoverage:
    if not isinstance(raw, dict):
        raise RuntimeTraceError("runtime trace coverage record is missing")
    required = _event_types(raw.get("required_event_types"), "coverage.required_event_types")
    observed = _event_types(raw.get("observed_event_types"), "coverage.observed_event_types")
    missing = _event_types(raw.get("missing_event_types"), "coverage.missing_event_types")
    require_exit_zero = _boolean(raw.get("require_exit_zero"), "coverage.require_exit_zero")
    exit_satisfied = _boolean(
        raw.get("exit_status_satisfied"), "coverage.exit_status_satisfied"
    )
    complete = _boolean(raw.get("complete"), "coverage.complete")
    actual_observed = tuple(
        sorted(
            {event.event_type for event in events if event.event_type != RuntimeEventType.HARNESS},
            key=lambda item: item.value,
        )
    )
    actual_missing = tuple(item for item in required if item not in actual_observed)
    actual_exit_satisfied = exit_status.startswith("exit-") and (
        not require_exit_zero or exit_status == "exit-0"
    )
    actual_complete = not actual_missing and actual_exit_satisfied
    if (
        observed != actual_observed
        or missing != actual_missing
        or exit_satisfied != actual_exit_satisfied
        or complete != actual_complete
    ):
        raise RuntimeTraceError("runtime trace coverage assertions do not match observations")
    return RuntimeCoverage(
        required_event_types=required,
        observed_event_types=observed,
        missing_event_types=missing,
        require_exit_zero=require_exit_zero,
        exit_status_satisfied=exit_satisfied,
        complete=complete,
    )


def _timestamp(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeTraceError(f"invalid timestamp field: {field}") from exc
    if parsed.tzinfo is None:
        raise RuntimeTraceError(f"timestamp must include a timezone: {field}")
    return parsed


def load_runtime_trace(
    path: Path,
    *,
    expected_artifact_sha256: str,
    signature_path: Path | None = None,
    allowed_signers: Path | None = None,
    signature_identity: str = "hanna2",
    expected_base_image_sha256: str | None = None,
    expected_host_policy_sha256: str | None = None,
) -> RuntimeTrace:
    """Load a trace, bind it to an artifact, and optionally authenticate it."""
    payload = _regular_file(path, MAX_TRACE_BYTES)
    try:
        raw = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeTraceError("runtime trace is not valid JSON") from exc
    if not isinstance(raw, dict) or raw.get("schema_version") not in {"1.0", "1.1", "1.2"}:
        raise RuntimeTraceError("unsupported runtime trace schema")
    schema_version = raw["schema_version"]
    artifact_sha256 = _digest(raw.get("artifact_sha256"), "artifact_sha256")
    if artifact_sha256 != expected_artifact_sha256.lower():
        raise RuntimeTraceError("runtime trace artifact does not match scanned artifact")
    run_id = _text(raw.get("run_id"), "run_id", required=True) or ""
    if not _RUN_ID_RE.fullmatch(run_id):
        raise RuntimeTraceError("invalid runtime trace run_id")
    isolation_data = raw.get("isolation")
    if not isinstance(isolation_data, dict):
        raise RuntimeTraceError("runtime trace isolation record is missing")
    isolation = IsolationRecord(
        hypervisor=_text(
            isolation_data.get("hypervisor"), "isolation.hypervisor", required=True
        ) or "",
        hardware_virtualization=_boolean(
            isolation_data.get("hardware_virtualization"),
            "isolation.hardware_virtualization",
        ),
        ephemeral_disk=_boolean(
            isolation_data.get("ephemeral_disk"), "isolation.ephemeral_disk"
        ),
        host_shares=_boolean(isolation_data.get("host_shares"), "isolation.host_shares"),
        host_credentials=_boolean(
            isolation_data.get("host_credentials"), "isolation.host_credentials"
        ),
        network_policy=_text(
            isolation_data.get("network_policy"),
            "isolation.network_policy",
            required=True,
        ) or "",
        base_image_sha256=_digest(
            isolation_data.get("base_image_sha256"), "isolation.base_image_sha256"
        ),
        candidate_read_only=_boolean(
            isolation_data.get("candidate_read_only"),
            "isolation.candidate_read_only",
        ),
        external_network_interfaces=(
            _string_list(
                isolation_data.get("external_network_interfaces"),
                "isolation.external_network_interfaces",
            )
            if schema_version == "1.2"
            else ()
        ),
        sinkhole_local=(
            _boolean(isolation_data.get("sinkhole_local"), "isolation.sinkhole_local")
            if schema_version == "1.2"
            else False
        ),
    )
    base_image_verified = False
    if expected_base_image_sha256 is not None:
        expected_base = _digest(expected_base_image_sha256, "expected_base_image_sha256")
        if isolation.base_image_sha256 != expected_base:
            raise RuntimeTraceError("runtime trace base image does not match approved image")
        base_image_verified = True
    campaign_id = None
    specimen_class = None
    host_policy_sha256 = None
    host_policy_verified = False
    if schema_version == "1.2":
        harness = raw.get("harness")
        if not isinstance(harness, dict):
            raise RuntimeTraceError("runtime trace harness record is missing")
        campaign_id = _text(harness.get("campaign_id"), "harness.campaign_id", required=True)
        specimen_class = _text(
            harness.get("specimen_class"), "harness.specimen_class", required=True
        )
        if specimen_class not in {"fixture", "corpus"}:
            raise RuntimeTraceError("runtime trace specimen class is invalid")
        host_policy_sha256 = _digest(
            harness.get("host_policy_sha256"), "harness.host_policy_sha256"
        )
        if expected_host_policy_sha256 is not None:
            expected_policy = _digest(
                expected_host_policy_sha256, "expected_host_policy_sha256"
            )
            if host_policy_sha256 != expected_policy:
                raise RuntimeTraceError("runtime trace host policy does not match approved policy")
            host_policy_verified = True
    events_raw = raw.get("events")
    if not isinstance(events_raw, list) or len(events_raw) > MAX_EVENTS:
        raise RuntimeTraceError(f"runtime trace exceeds {MAX_EVENTS} events")
    signature_verified = False
    warnings = []
    if signature_path is not None or allowed_signers is not None:
        if signature_path is None or allowed_signers is None:
            raise RuntimeTraceError(
                "both signature and allowed-signers files are required"
            )
        signature_verified = verify_trace_signature(
            payload,
            signature_path,
            allowed_signers,
            identity=signature_identity,
        )
        if not signature_verified:
            raise RuntimeTraceError("runtime trace signature verification failed")
    else:
        warnings.append("runtime trace is not authenticated")
    if not base_image_verified:
        warnings.append("runtime trace base image was not matched to an approved digest")
    if schema_version == "1.2" and not host_policy_verified:
        warnings.append("runtime trace host policy was not matched to an approved digest")
    if not isolation.valid:
        warnings.append("runtime isolation record does not satisfy WAINGRO policy")
    started_at = _text(raw.get("started_at"), "started_at", required=True) or ""
    finished_at = _text(raw.get("finished_at"), "finished_at", required=True) or ""
    started = _timestamp(started_at, "started_at")
    finished = _timestamp(finished_at, "finished_at")
    if finished < started:
        raise RuntimeTraceError("runtime trace finished before it started")
    events = tuple(_event(item, index) for index, item in enumerate(events_raw))
    if any(
        not started <= _timestamp(event.timestamp, "event.timestamp") <= finished
        for event in events
    ):
        raise RuntimeTraceError("runtime event timestamp falls outside the trace interval")
    exit_status = _text(raw.get("exit_status"), "exit_status", required=True) or ""
    coverage = (
        _coverage(raw.get("coverage"), events, exit_status)
        if schema_version in {"1.1", "1.2"}
        else None
    )
    return RuntimeTrace(
        run_id=run_id,
        artifact_sha256=artifact_sha256,
        host=_text(raw.get("host"), "host", required=True) or "",
        backend=_text(raw.get("backend"), "backend", required=True) or "",
        started_at=started_at,
        finished_at=finished_at,
        exit_status=exit_status,
        isolation=isolation,
        events=events,
        trace_sha256=hashlib.sha256(payload).hexdigest(),
        signature_verified=signature_verified,
        signature_identity=signature_identity if signature_verified else None,
        base_image_verified=base_image_verified,
        host_policy_verified=host_policy_verified,
        coverage=coverage,
        warnings=tuple(warnings),
        schema_version=schema_version,
        campaign_id=campaign_id,
        specimen_class=specimen_class,
        host_policy_sha256=host_policy_sha256,
    )
