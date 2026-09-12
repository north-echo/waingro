"""Guest-only telemetry agent embedded into the hanna2 analysis image.

This module is data for :mod:`waingro.dynamic.runner`; it must never be invoked
on the scanner host.  It executes one explicitly authorized argv vector as the
unprivileged ``waingro`` guest account and emits a bounded trace on ttyS0.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pwd
import re
import shutil
import signal
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

INPUT = Path("/run/waingro-input")
CANDIDATE = Path("/opt/waingro/candidate")
TRACE_DIR = Path("/run/waingro-trace")
MAX_EVENTS = 100_000
MAX_TRACE_BYTES = 20 * 1024 * 1024


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _scope_hash(files: list[dict]) -> str:
    digest = hashlib.sha256()
    for item in sorted(files, key=lambda record: record["path"]):
        relative = item["path"]
        path_bytes = relative.encode("utf-8")
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        digest.update(item["size_bytes"].to_bytes(8, "big"))
        digest.update(bytes.fromhex(item["sha256"]))
    return digest.hexdigest()


def _mount_input() -> None:
    INPUT.mkdir(mode=0o700, parents=True, exist_ok=True)
    device = Path("/dev/disk/by-label/cidata")
    if not device.exists():
        device = Path("/dev/sr0")
    subprocess.run(  # noqa: S603 -- fixed guest device and destination.
        ["/usr/bin/mount", "-o", "ro,nosuid,nodev,noexec", str(device), str(INPUT)],
        check=True,
        timeout=15,
        env={"PATH": "/usr/sbin:/usr/bin"},
    )


def _copy_candidate(plan: dict) -> None:
    records = plan["artifact"]["files"]
    if _scope_hash(records) != plan["artifact"]["sha256"]:
        raise RuntimeError("plan artifact record is internally inconsistent")
    CANDIDATE.mkdir(mode=0o700, parents=True, exist_ok=False)
    source_root = INPUT / "candidate"
    for item in records:
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts or len(relative.parts) > 2:
            raise RuntimeError("candidate path violates depth policy")
        source = source_root / relative
        if source.is_symlink() or not source.is_file():
            raise RuntimeError("candidate source is not a regular file")
        if source.stat().st_size != item["size_bytes"] or _hash(source) != item["sha256"]:
            raise RuntimeError("candidate file does not match authorized artifact")
        destination = CANDIDATE / relative
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with source.open("rb") as reader, destination.open("xb") as writer:
            shutil.copyfileobj(reader, writer, length=1024 * 1024)
        destination.chmod(0o444)
    account = pwd.getpwnam("waingro")
    for directory, dirs, files in os.walk(CANDIDATE):
        Path(directory).chmod(0o555)
        os.chown(directory, account.pw_uid, account.pw_gid)
        for name in dirs:
            child = Path(directory) / name
            child.chmod(0o555)
            os.chown(child, account.pw_uid, account.pw_gid)
        for name in files:
            os.chown(Path(directory) / name, account.pw_uid, account.pw_gid)


def _synthetic_home() -> dict[str, str]:
    account = pwd.getpwnam("waingro")
    home = Path(account.pw_dir)
    (home / ".aws").mkdir(mode=0o700, parents=True, exist_ok=True)
    (home / ".config").mkdir(mode=0o700, exist_ok=True)
    (home / ".ssh").mkdir(mode=0o700, exist_ok=True)
    (home / ".aws" / "credentials").write_text(
        "[default]\naws_access_key_id=WAINGRO_CANARY_ACCESS\n"
        "aws_secret_access_key=WAINGRO_CANARY_SECRET\n",
        encoding="utf-8",
    )
    (home / ".config" / "waingro-canary-token").write_text(
        "WAINGRO_CANARY_TOKEN\n", encoding="utf-8"
    )
    (home / ".ssh" / "id_ed25519").write_text(
        "WAINGRO_SYNTHETIC_SSH_PRIVATE_KEY_CANARY\n", encoding="utf-8"
    )
    for directory, dirs, files in os.walk(home):
        os.chown(directory, account.pw_uid, account.pw_gid)
        for name in dirs:
            os.chown(Path(directory) / name, account.pw_uid, account.pw_gid)
        for name in files:
            os.chown(Path(directory) / name, account.pw_uid, account.pw_gid)
    return {
        "HOME": str(home),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "AWS_ACCESS_KEY_ID": "WAINGRO_CANARY_ACCESS",
        "AWS_SECRET_ACCESS_KEY": "WAINGRO_CANARY_SECRET",
        "GITHUB_TOKEN": "WAINGRO_CANARY_GITHUB_TOKEN",
        "OPENAI_API_KEY": "WAINGRO_CANARY_OPENAI_KEY",
        "WAINGRO_DYNAMIC": "1",
    }


def _argv(plan: dict) -> list[str]:
    scenario = plan["execution"].get("scenario")
    if not plan["execution"].get("authorized") or not isinstance(scenario, dict):
        raise RuntimeError("execution plan is not explicitly authorized")
    interpreters = {
        "python": "/usr/bin/python3",
        "node": "/usr/bin/node",
        "shell": "/usr/bin/bash",
    }
    interpreter = interpreters.get(scenario.get("interpreter"))
    entrypoint = scenario.get("entrypoint")
    arguments = scenario.get("arguments")
    if not interpreter or not isinstance(entrypoint, str) or not isinstance(arguments, list):
        raise RuntimeError("invalid execution scenario")
    candidate = (CANDIDATE / entrypoint).resolve()
    if CANDIDATE not in candidate.parents or not candidate.is_file():
        raise RuntimeError("scenario entrypoint is outside the candidate")
    if not Path(interpreter).is_file():
        raise RuntimeError(f"base image lacks scenario interpreter: {interpreter}")
    return [interpreter, str(candidate), *arguments]


def _run(plan: dict, argv: list[str], environment: dict[str, str]) -> tuple[str, str]:
    strace = Path("/usr/bin/strace")
    runuser = Path("/usr/sbin/runuser")
    if not strace.is_file() or not runuser.is_file():
        raise RuntimeError("base image contract requires strace and runuser")
    TRACE_DIR.mkdir(mode=0o700, parents=True, exist_ok=False)
    trace_prefix = TRACE_DIR / "strace"
    command = [
        str(strace),
        "-ff",
        "-ttt",
        "-s",
        "2048",
        "-yy",
        "-e",
        "trace=%process,%file,%network",
        "-o",
        str(trace_prefix),
        str(runuser),
        "-u",
        "waingro",
        "--",
        *argv,
    ]
    output = TRACE_DIR / "candidate-output.txt"
    timeout = int(plan["execution"]["timeout_seconds"])
    with output.open("wb") as handle:
        process = subprocess.Popen(  # noqa: S603 -- argv is artifact-bound and VM-only.
            command,
            cwd=CANDIDATE,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            return_code = process.wait(timeout=timeout)
            return f"exit-{return_code}", _hash(output)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
            return "timeout", _hash(output)


def _event(
    event_type: str,
    action: str,
    pid: int,
    *,
    timestamp: str | None = None,
    success: bool = True,
    **values,
) -> dict:
    return {
        "type": event_type,
        "action": action,
        "timestamp": timestamp or _now(),
        "process_id": pid,
        "success": success,
        **{key: value for key, value in values.items() if value is not None},
    }


def _connect_event_type(call: str) -> str | None:
    """Return externally relevant socket type; ignore local IPC transports."""
    if "sa_family=AF_INET" not in call:
        return None
    return "dns" if re.search(r"sin6?_port=htons\(53\)", call) else "network"


def _parse_events() -> list[dict]:
    events = []
    sensitive = ("/.aws/", "/.ssh/", "waingro-canary", "/proc/self/environ")
    persistence = ("/etc/cron", "/etc/systemd", "/.config/autostart", "/.bashrc")
    for path in sorted(TRACE_DIR.glob("strace.*")):
        try:
            pid = int(path.name.rsplit(".", 1)[-1])
        except ValueError:
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if len(events) >= MAX_EVENTS:
                return events
            stamp, separator, call = line.partition(" ")
            timestamp = _now()
            if separator:
                try:
                    timestamp = datetime.fromtimestamp(float(stamp), UTC).isoformat()
                except ValueError:
                    call = line
            success = not re.search(r"= -1 [A-Z]", call)
            quoted = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', call)
            target = quoted[0][:4096] if quoted else None
            if call.startswith(("execve(", "execveat(")) and success:
                events.append(_event(
                    "process", "exec", pid, timestamp=timestamp,
                    process=target, command=call[:4096],
                ))
            elif call.startswith("connect("):
                event_type = _connect_event_type(call)
                if event_type is not None:
                    events.append(_event(
                        event_type, "connect", pid, timestamp=timestamp,
                        success=success, destination=call[:4096],
                    ))
            elif (
                target
                and call.startswith(("open(", "openat(", "openat2("))
                and not any(flag in call for flag in ("O_WRONLY", "O_CREAT"))
                and any(marker in target for marker in sensitive)
                and success
            ):
                events.append(_event(
                    "credential", "read", pid, timestamp=timestamp, target=target,
                ))
            elif (
                target
                and any(flag in call for flag in ("O_WRONLY", "O_RDWR", "O_CREAT"))
            ):
                event_type = (
                    "persistence"
                    if any(marker in target for marker in persistence)
                    else "file"
                )
                events.append(_event(
                    event_type, "write", pid, timestamp=timestamp,
                    success=success, target=target,
                ))
    return events


def _emit(trace: dict) -> None:
    payload = json.dumps(trace, separators=(",", ":"), sort_keys=True).encode()
    if len(payload) > MAX_TRACE_BYTES:
        raise RuntimeError("runtime trace exceeded 20 MiB")
    encoded = base64.b64encode(payload).decode("ascii")
    with Path("/dev/ttyS0").open("w", encoding="ascii") as serial:
        serial.write("WAINGRO_TRACE_BEGIN\n")
        for offset in range(0, len(encoded), 4096):
            serial.write(encoded[offset : offset + 4096] + "\n")
        serial.write("WAINGRO_TRACE_END\n")
        serial.flush()


def main() -> None:
    started = _now()
    run_id = "unknown"
    artifact_sha256 = "0" * 64
    base_sha256 = "0" * 64
    network_policy = "none"
    events = []
    exit_status = "harness-error"
    output_sha256 = None
    error = None
    try:
        _mount_input()
        plan = json.loads((INPUT / "plan.json").read_text(encoding="utf-8"))
        run_id = plan["job_id"]
        artifact_sha256 = plan["artifact"]["sha256"]
        base_sha256 = plan["execution"]["base_image_sha256"]
        network_policy = plan["execution"]["network_policy"]
        _copy_candidate(plan)
        environment = _synthetic_home()
        exit_status, output_sha256 = _run(plan, _argv(plan), environment)
        events = _parse_events()
    except Exception as exc:  # Guest errors must still produce a bounded receipt.
        error = f"{type(exc).__name__}: {exc}"[:1000]
    trace = {
        "schema_version": "1.0",
        "run_id": run_id,
        "artifact_sha256": artifact_sha256,
        "host": "hanna2",
        "backend": "libvirt-kvm",
        "started_at": started,
        "finished_at": _now(),
        "exit_status": exit_status,
        "isolation": {
            "hypervisor": "libvirt-kvm",
            "hardware_virtualization": True,
            "ephemeral_disk": True,
            "host_shares": False,
            "host_credentials": False,
            "network_policy": network_policy,
            "base_image_sha256": base_sha256,
            "candidate_read_only": True,
        },
        "events": events,
        "harness": {
            "error": error,
            "candidate_output_sha256": output_sha256,
            "event_count": len(events),
        },
    }
    _emit(trace)
    time.sleep(1)
    subprocess.run(  # noqa: S603 -- fixed guest shutdown action.
        ["/usr/bin/systemctl", "poweroff", "--no-block"],
        check=False,
        timeout=10,
        env={"PATH": "/usr/bin:/bin"},
    )


if __name__ == "__main__":
    main()
