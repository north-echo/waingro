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
import resource
import shutil
import signal
import socket
import struct
import subprocess
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

INPUT = Path("/run/waingro-input")
CANDIDATE = Path("/opt/waingro/candidate")
TRACE_DIR = Path("/run/waingro-trace")
MAX_EVENTS = 100_000
MAX_TRACE_BYTES = 20 * 1024 * 1024
MAX_CANDIDATE_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_STRACE_BYTES = 64 * 1024 * 1024
_SINKHOLE_EVENTS: list[dict] = []
_SINKHOLE_LOCK = threading.Lock()


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
    for directory, dirs, files in os.walk(CANDIDATE):
        Path(directory).chmod(0o555)
        for name in dirs:
            child = Path(directory) / name
            child.chmod(0o555)
        for name in files:
            child = Path(directory) / name
            child.chmod(0o444)
            os.chown(child, 0, 0)
        os.chown(directory, 0, 0)


def _synthetic_value(name: str, profile: str) -> str:
    suffix = hashlib.sha256(f"{name}:{profile}".encode()).hexdigest()[:20].upper()
    prefixes = {
        "access-key": "WAINGRO_CANARY_ACCESS",
        "api-key": "WAINGRO_CANARY_API_KEY",
        "password": "WAINGRO_CANARY_PASSWORD",
        "secret-key": "WAINGRO_CANARY_SECRET",
        "token": "WAINGRO_CANARY_TOKEN",
    }
    return f"{prefixes[profile]}_{suffix}"


def _synthetic_home(plan: dict) -> dict[str, str]:
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
    environment = {
        "HOME": str(home),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "AWS_ACCESS_KEY_ID": "WAINGRO_CANARY_ACCESS",
        "AWS_SECRET_ACCESS_KEY": "WAINGRO_CANARY_SECRET",
        "GITHUB_TOKEN": "WAINGRO_CANARY_GITHUB_TOKEN",
        "OPENAI_API_KEY": "WAINGRO_CANARY_OPENAI_KEY",
        "WAINGRO_DYNAMIC": "1",
    }
    scenario = plan["execution"]["scenario"]
    for name, profile in scenario["synthetic_environment"].items():
        environment[name] = _synthetic_value(name, profile)
    return environment


def _validate_guest_contract(plan: dict) -> None:
    scenario = plan["execution"]["scenario"]
    missing = [
        executable
        for executable in scenario["required_executables"]
        if shutil.which(
            executable,
            path="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        )
        is None
    ]
    if missing:
        raise RuntimeError("base image lacks required executables: " + ", ".join(missing))


def _record_sinkhole_event(event: dict) -> None:
    with _SINKHOLE_LOCK:
        if len(_SINKHOLE_EVENTS) < MAX_EVENTS:
            _SINKHOLE_EVENTS.append(event)


def _dns_name(payload: bytes) -> tuple[str, int, int] | None:
    if len(payload) < 17:
        return None
    labels = []
    offset = 12
    while offset < len(payload):
        size = payload[offset]
        offset += 1
        if size == 0:
            break
        if size > 63 or offset + size > len(payload):
            return None
        labels.append(payload[offset : offset + size].decode("ascii", errors="replace"))
        offset += size
    if not labels or offset + 4 > len(payload):
        return None
    query_type = int.from_bytes(payload[offset : offset + 2], "big")
    return ".".join(labels)[:253], query_type, offset + 4


def _dns_sinkhole(server: socket.socket) -> None:
    while True:
        try:
            payload, peer = server.recvfrom(4096)
            parsed = _dns_name(payload)
            if parsed is None:
                continue
            name, query_type, question_end = parsed
            _record_sinkhole_event(_event(
                "dns",
                "sinkhole-query",
                0,
                destination=name,
                labels=["loopback-sinkhole"],
            ))
            answer = b""
            if query_type == 1:
                answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + b"\x7f\x00\x00\x01"
            elif query_type == 28:
                answer = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 0, 16) + (b"\x00" * 15) + b"\x01"
            flags = b"\x81\x80"
            counts = b"\x00\x01" + (b"\x00\x01" if answer else b"\x00\x00") + b"\x00\x00\x00\x00"
            server.sendto(payload[:2] + flags + counts + payload[12:question_end] + answer, peer)
        except OSError:
            return


def _http_sinkhole(server: socket.socket, *, tls: bool = False) -> None:
    while True:
        try:
            connection, _peer = server.accept()
        except OSError:
            return
        with connection:
            connection.settimeout(1)
            try:
                payload = connection.recv(64 * 1024)
            except OSError:
                payload = b""
            labels = ["loopback-sinkhole"]
            if b"WAINGRO_CANARY_" in payload or b"WAINGRO_SYNTHETIC_" in payload:
                labels.append("synthetic-canary")
            destination = "127.0.0.1:443" if tls else "127.0.0.1:80"
            target = "tls-client-hello" if tls else "http-request"
            if not tls:
                text = payload.decode("iso-8859-1", errors="replace")
                lines = text.splitlines()
                if lines:
                    parts = lines[0].split()
                    if len(parts) >= 2:
                        target = parts[1][:2048]
                for line in lines[1:]:
                    name, separator, value = line.partition(":")
                    if separator and name.lower() == "host":
                        destination = value.strip()[:253]
                        break
            _record_sinkhole_event(_event(
                "network",
                "sinkhole-connect" if tls else "sinkhole-request",
                0,
                target=target,
                destination=destination,
                labels=labels,
            ))
            if not tls:
                try:  # noqa: SIM105 -- this file is copied into a minimal guest image.
                    connection.sendall(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                except OSError:
                    pass


def _start_loopback_sinkhole(plan: dict) -> None:
    if plan["execution"]["network_policy"] != "loopback-sinkhole":
        return
    resolver = Path("/etc/resolv.conf")
    if resolver.is_symlink():
        resolver.unlink()
    resolver.write_text("nameserver 127.0.0.1\noptions attempts:1 timeout:1\n", encoding="ascii")
    listeners = []
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind(("127.0.0.1", 53))
    listeners.append((udp, _dns_sinkhole, {}))
    for port, tls in ((80, False), (443, True)):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind(("127.0.0.1", port))
        tcp.listen(16)
        listeners.append((tcp, _http_sinkhole, {"tls": tls}))
    for listener, target, kwargs in listeners:
        threading.Thread(target=target, args=(listener,), kwargs=kwargs, daemon=True).start()


def _limit_candidate() -> None:
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (MAX_CANDIDATE_OUTPUT_BYTES, MAX_CANDIDATE_OUTPUT_BYTES),
    )
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_NPROC, (128, 128))


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
            preexec_fn=_limit_candidate,  # noqa: S606 -- guest-only resource boundary.
        )
        deadline = time.monotonic() + timeout
        status = "completed"
        while process.poll() is None:
            if time.monotonic() >= deadline:
                status = "timeout"
                break
            trace_bytes = sum(path.stat().st_size for path in TRACE_DIR.glob("strace.*"))
            if trace_bytes > MAX_STRACE_BYTES or output.stat().st_size > MAX_CANDIDATE_OUTPUT_BYTES:
                status = "resource-limit"
                break
            time.sleep(0.1)
        if status != "completed":
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
            return status, _hash(output)
        return f"exit-{process.returncode}", _hash(output)


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
    trace_paths = sorted(TRACE_DIR.glob("strace.*"))
    parents: dict[int, int] = {}
    process_result = re.compile(r"^(?:clone|clone3|fork|vfork)\(.*\)\s+=\s+(\d+)$")
    for path in trace_paths:
        try:
            pid = int(path.name.rsplit(".", 1)[-1])
        except ValueError:
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            _stamp, _separator, call = line.partition(" ")
            if match := process_result.match(call):
                parents[int(match.group(1))] = pid
    for path in trace_paths:
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
                    parent_process_id=parents.get(pid), process=target, command=call[:4096],
                ))
            elif call.startswith("connect("):
                event_type = _connect_event_type(call)
                if event_type is not None:
                    events.append(_event(
                        event_type, "connect", pid, timestamp=timestamp,
                        parent_process_id=parents.get(pid), success=success,
                        destination=call[:4096],
                    ))
            elif (
                target
                and call.startswith(("open(", "openat(", "openat2("))
                and not any(flag in call for flag in ("O_WRONLY", "O_CREAT"))
                and any(marker in target for marker in sensitive)
                and success
            ):
                events.append(_event(
                    "credential", "read", pid, timestamp=timestamp,
                    parent_process_id=parents.get(pid), target=target,
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
                    parent_process_id=parents.get(pid), success=success, target=target,
                ))
    with _SINKHOLE_LOCK:
        events.extend(_SINKHOLE_EVENTS[: max(0, MAX_EVENTS - len(events))])
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
        _validate_guest_contract(plan)
        environment = _synthetic_home(plan)
        _start_loopback_sinkhole(plan)
        exit_status, output_sha256 = _run(plan, _argv(plan), environment)
        events = _parse_events()
    except Exception as exc:  # Guest errors must still produce a bounded receipt.
        error = f"{type(exc).__name__}: {exc}"[:1000]
    coverage_policy = (
        plan.get("execution", {}).get("scenario", {}).get("coverage", {})
        if "plan" in locals()
        else {}
    )
    required_types = coverage_policy.get("required_event_types", [])
    require_exit_zero = coverage_policy.get("require_exit_zero", False)
    observed_types = sorted({event["type"] for event in events if event["type"] != "harness"})
    missing_types = [item for item in required_types if item not in observed_types]
    exit_status_satisfied = exit_status.startswith("exit-") and (
        not require_exit_zero or exit_status == "exit-0"
    )
    trace = {
        "schema_version": "1.2",
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
            "external_network_interfaces": sorted(
                path.name for path in Path("/sys/class/net").iterdir() if path.name != "lo"
            ),
            "sinkhole_local": network_policy == "loopback-sinkhole",
            "base_image_sha256": base_sha256,
            "candidate_read_only": True,
        },
        "events": events,
        "coverage": {
            "required_event_types": required_types,
            "observed_event_types": observed_types,
            "missing_event_types": missing_types,
            "require_exit_zero": require_exit_zero,
            "exit_status_satisfied": exit_status_satisfied,
            "complete": not missing_types and exit_status_satisfied,
        },
        "harness": {
            "error": error,
            "candidate_output_sha256": output_sha256,
            "event_count": len(events),
            "campaign_id": (
                plan.get("execution", {}).get("campaign_id") if "plan" in locals() else None
            ),
            "specimen_class": (
                plan.get("execution", {}).get("specimen_class")
                if "plan" in locals()
                else None
            ),
            "host_policy_sha256": (
                plan.get("execution", {}).get("host_policy_sha256")
                if "plan" in locals()
                else None
            ),
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
