"""Fail-closed libvirt/KVM runner for explicitly authorized hanna2 jobs.

This backend is intentionally unavailable on other hosts.  It never exposes a
host directory to the guest: the exact statically scanned file set is copied to
a read-only NoCloud ISO, and all disk writes go to a disposable qcow2 overlay.
"""

from __future__ import annotations

import base64
import binascii
import errno
import fcntl
import hashlib
import json
import os
import pty
import re
import select
import shutil
import socket
import stat
import subprocess
import tempfile
import termios
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import yaml

from waingro.dynamic.plan import dynamic_job_id
from waingro.dynamic.trace import MAX_TRACE_BYTES, load_runtime_trace
from waingro.scanner import scan_skill

MAX_PLAN_BYTES = 2 * 1024 * 1024
TRACE_BEGIN = "WAINGRO_TRACE_BEGIN"
TRACE_END = "WAINGRO_TRACE_END"
_JOB_RE = re.compile(r"^waingro-[0-9a-f]{20}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.qcow2$")
_ENTRYPOINT_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?$")
MAX_ARTIFACT_FILES = 10_000
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024


class DynamicRunnerError(RuntimeError):
    """The dynamic job or hanna2 host failed a safety requirement."""


@dataclass(frozen=True)
class DynamicRunResult:
    job_id: str
    trace_path: str
    trace_sha256: str
    signature_path: str | None
    exit_status: str
    event_count: int
    timed_out: bool

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "trace_path": self.trace_path,
            "trace_sha256": self.trace_sha256,
            "signature_path": self.signature_path,
            "exit_status": self.exit_status,
            "event_count": self.event_count,
            "timed_out": self.timed_out,
        }


def _bounded_regular_file(path: Path, max_bytes: int | None = None) -> bytes:
    if path.is_symlink():
        raise DynamicRunnerError(f"symlink is not accepted: {path}")
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    if not stat.S_ISREG(info.st_mode):
        raise DynamicRunnerError(f"not a regular file: {resolved}")
    if max_bytes is not None and info.st_size > max_bytes:
        raise DynamicRunnerError(f"file exceeds {max_bytes} bytes: {resolved}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(resolved, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise DynamicRunnerError(f"file changed while opening: {resolved}")
        digest = hashlib.sha256()
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise DynamicRunnerError(f"file exceeds {max_bytes} bytes: {resolved}")
            digest.update(chunk)
            if max_bytes is not None:
                chunks.append(chunk)
    finally:
        os.close(descriptor)
    return b"".join(chunks) if max_bytes is not None else digest.hexdigest().encode()


def _load_plan(path: Path) -> dict:
    payload = _bounded_regular_file(path, MAX_PLAN_BYTES)
    try:
        plan = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DynamicRunnerError("dynamic plan is not valid JSON") from exc
    if not isinstance(plan, dict) or plan.get("schema_version") != "1.0":
        raise DynamicRunnerError("unsupported dynamic plan schema")
    job_id = plan.get("job_id")
    artifact = plan.get("artifact")
    execution = plan.get("execution")
    if not isinstance(job_id, str) or not _JOB_RE.fullmatch(job_id):
        raise DynamicRunnerError("invalid dynamic job id")
    if dynamic_job_id(plan) != job_id:
        raise DynamicRunnerError("dynamic plan changed after its job id was issued")
    if not isinstance(artifact, dict) or not isinstance(execution, dict):
        raise DynamicRunnerError("dynamic plan is missing artifact or execution data")
    if execution.get("authorized") is not True:
        raise DynamicRunnerError("dynamic execution was not explicitly authorized")
    if execution.get("expected_host") != "hanna2" or execution.get("backend") != "libvirt-kvm":
        raise DynamicRunnerError("dynamic plan targets an unsupported host or backend")
    if execution.get("host_shares") is not False or execution.get("host_credentials") is not False:
        raise DynamicRunnerError("dynamic plan requests forbidden host access")
    if execution.get("disk_mode") != "ephemeral-overlay":
        raise DynamicRunnerError("dynamic plan does not require an ephemeral overlay")
    if execution.get("candidate_transport") != "read-only-iso":
        raise DynamicRunnerError("dynamic plan does not require read-only ISO transport")
    if execution.get("synthetic_credentials") is not True:
        raise DynamicRunnerError("dynamic plan does not require synthetic credentials")
    if execution.get("network_policy") != "none":
        raise DynamicRunnerError("dynamic plan requests a forbidden network policy")
    digest = artifact.get("sha256")
    base_digest = execution.get("base_image_sha256")
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
        raise DynamicRunnerError("dynamic plan has an invalid artifact digest")
    if not isinstance(base_digest, str) or not _DIGEST_RE.fullmatch(base_digest):
        raise DynamicRunnerError("dynamic plan has an invalid base image digest")
    base_image = execution.get("base_image")
    if (
        not isinstance(base_image, str)
        or Path(base_image).name != base_image
        or not _IMAGE_RE.fullmatch(base_image)
    ):
        raise DynamicRunnerError("dynamic plan has an invalid base image name")
    timeout = execution.get("timeout_seconds")
    memory = execution.get("memory_mib")
    if not isinstance(timeout, int) or not 10 <= timeout <= 300:
        raise DynamicRunnerError("dynamic timeout violates policy")
    if not isinstance(memory, int) or not 256 <= memory <= 2048:
        raise DynamicRunnerError("dynamic memory violates policy")
    if execution.get("vcpus") != 1:
        raise DynamicRunnerError("dynamic vCPU count violates policy")
    scenario = execution.get("scenario")
    if not isinstance(scenario, dict):
        raise DynamicRunnerError("authorized dynamic plan has no scenario")
    if scenario.get("interpreter") not in {"python", "node", "shell"}:
        raise DynamicRunnerError("dynamic scenario interpreter violates policy")
    entrypoint = scenario.get("entrypoint")
    arguments = scenario.get("arguments")
    if not isinstance(entrypoint, str) or not isinstance(arguments, list):
        raise DynamicRunnerError("dynamic scenario is malformed")
    relative = PurePosixPath(entrypoint)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or len(relative.parts) > 2
        or not _ENTRYPOINT_RE.fullmatch(entrypoint)
    ):
        raise DynamicRunnerError("dynamic scenario entrypoint violates path policy")
    if len(arguments) > 32 or any(
        not isinstance(arg, str) or len(arg) > 1024 or "\0" in arg
        for arg in arguments
    ):
        raise DynamicRunnerError("dynamic scenario arguments violate policy")
    allowed_suffixes = {
        "python": {".py"},
        "node": {".js", ".mjs", ".cjs"},
        "shell": {".sh"},
    }
    if relative.suffix.lower() not in allowed_suffixes[scenario["interpreter"]]:
        raise DynamicRunnerError("dynamic scenario interpreter and entrypoint disagree")
    records = artifact.get("files")
    file_count = artifact.get("file_count")
    total_bytes = artifact.get("total_bytes")
    if (
        not isinstance(records, list)
        or not isinstance(file_count, int)
        or not 1 <= file_count <= MAX_ARTIFACT_FILES
        or len(records) != file_count
        or not isinstance(total_bytes, int)
        or not 0 <= total_bytes <= MAX_ARTIFACT_BYTES
    ):
        raise DynamicRunnerError("dynamic artifact file inventory is malformed")
    if any(not isinstance(item, dict) for item in records):
        raise DynamicRunnerError("invalid artifact file record")
    paths = []
    computed_total = 0
    scope_digest = hashlib.sha256()
    for item in sorted(records, key=lambda record: str(record.get("path", ""))):
        path_text = item.get("path")
        item_digest = item.get("sha256")
        size = item.get("size_bytes")
        if (
            not isinstance(path_text, str)
            or not isinstance(item_digest, str)
            or not _DIGEST_RE.fullmatch(item_digest)
            or not isinstance(size, int)
            or not 0 <= size <= MAX_ARTIFACT_BYTES
        ):
            raise DynamicRunnerError("invalid artifact file record")
        item_path = PurePosixPath(path_text)
        if item_path.is_absolute() or ".." in item_path.parts or len(item_path.parts) > 2:
            raise DynamicRunnerError("artifact file path violates scope policy")
        paths.append(path_text)
        path_bytes = path_text.encode("utf-8")
        scope_digest.update(len(path_bytes).to_bytes(8, "big"))
        scope_digest.update(path_bytes)
        scope_digest.update(size.to_bytes(8, "big"))
        scope_digest.update(bytes.fromhex(item_digest))
        computed_total += size
    if len(paths) != len(set(paths)) or entrypoint not in paths:
        raise DynamicRunnerError("dynamic artifact inventory has duplicate or missing paths")
    if computed_total != total_bytes or scope_digest.hexdigest() != digest:
        raise DynamicRunnerError("dynamic artifact inventory does not match its digest")
    return plan


def _run_command(arguments: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess:
    executable = shutil.which(arguments[0])
    if executable is None:
        raise DynamicRunnerError(f"required executable is unavailable: {arguments[0]}")
    completed = subprocess.run(  # noqa: S603 -- argv only; no shell interpretation.
        [executable, *arguments[1:]],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()[:2000]
        raise DynamicRunnerError(f"command failed ({arguments[0]}): {detail}")
    return completed


def _establish_controlling_tty() -> None:
    """Create the controlling terminal required by ``virsh console``."""
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


def _capture_console_chunk(master_fd: int, output, total: int) -> tuple[int, bool]:
    """Copy one bounded PTY chunk; return byte count and whether the PTY closed."""
    ready, _, _ = select.select([master_fd], [], [], 0.5)
    if not ready:
        return total, False
    try:
        chunk = os.read(master_fd, 64 * 1024)
    except OSError as exc:
        if exc.errno == errno.EIO:
            return total, True
        raise
    if not chunk:
        return total, True
    total += len(chunk)
    if total > MAX_TRACE_BYTES * 2:
        raise DynamicRunnerError("guest console exceeded 40 MiB")
    output.write(chunk)
    output.flush()
    return total, False


def _verify_host(work_root: Path) -> None:
    if socket.gethostname().split(".", 1)[0] != "hanna2":
        raise DynamicRunnerError("dynamic execution is restricted to hanna2")
    if os.geteuid() == 0:
        raise DynamicRunnerError("dynamic runner may not execute as root")
    kvm = Path("/dev/kvm")
    if (
        not kvm.exists()
        or not stat.S_ISCHR(kvm.stat().st_mode)
        or not os.access(kvm, os.R_OK | os.W_OK)
    ):
        raise DynamicRunnerError("KVM hardware virtualization is unavailable")
    enforce = Path("/sys/fs/selinux/enforce")
    if not enforce.is_file() or enforce.read_text(encoding="ascii").strip() != "1":
        raise DynamicRunnerError("SELinux must be enforcing")
    if work_root.is_symlink():
        raise DynamicRunnerError("dynamic work root may not be a symlink")
    root = work_root.resolve(strict=True)
    info = root.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & stat.S_IWOTH:
        raise DynamicRunnerError("dynamic work root is not a protected directory")
    _run_command(["virsh", "-c", "qemu:///system", "uri"], timeout=10)


def _copy_artifact(candidate: Path, plan: dict, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    for item in plan["artifact"]["files"]:
        if not isinstance(item, dict):
            raise DynamicRunnerError("invalid artifact file record")
        relative_text = item.get("path")
        expected_digest = item.get("sha256")
        expected_size = item.get("size_bytes")
        if (
            not isinstance(relative_text, str)
            or not isinstance(expected_digest, str)
            or not _DIGEST_RE.fullmatch(expected_digest)
            or not isinstance(expected_size, int)
            or expected_size < 0
        ):
            raise DynamicRunnerError("invalid artifact file record")
        relative = PurePosixPath(relative_text)
        if relative.is_absolute() or ".." in relative.parts or len(relative.parts) > 2:
            raise DynamicRunnerError("artifact file path violates scope policy")
        source = candidate.joinpath(*relative.parts)
        payload = _bounded_regular_file(source, expected_size)
        if len(payload) != expected_size or hashlib.sha256(payload).hexdigest() != expected_digest:
            raise DynamicRunnerError("candidate changed after static assessment")
        target = destination.joinpath(*relative.parts)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    for directory, _dirs, _files in os.walk(destination, topdown=False):
        Path(directory).chmod(0o555)


def _guest_agent_bytes() -> bytes:
    path = Path(__file__).with_name("guest_agent_payload.py")
    return _bounded_regular_file(path, 1024 * 1024)


def _write_input_tree(stage: Path, plan_path: Path, candidate: Path, plan: dict) -> None:
    stage.mkdir(mode=0o700)
    candidate_stage = stage / "candidate"
    _copy_artifact(candidate, plan, candidate_stage)
    (stage / "plan.json").write_bytes(_bounded_regular_file(plan_path, MAX_PLAN_BYTES))
    (stage / "meta-data").write_text(
        f"instance-id: {plan['job_id']}\nlocal-hostname: waingro-guest\n",
        encoding="utf-8",
    )
    cloud_config = {
        "users": [{
            "name": "waingro",
            "lock_passwd": True,
            "shell": "/sbin/nologin",
            "no_create_home": False,
        }],
        "ssh_pwauth": False,
        "disable_root": True,
        "write_files": [{
            "path": "/usr/local/libexec/waingro-guest-agent.py",
            "owner": "root:root",
            "permissions": "0500",
            "encoding": "b64",
            "content": base64.b64encode(_guest_agent_bytes()).decode("ascii"),
        }],
        "runcmd": [["/usr/bin/python3", "/usr/local/libexec/waingro-guest-agent.py"]],
    }
    (stage / "user-data").write_text(
        "#cloud-config\n" + yaml.safe_dump(cloud_config, sort_keys=True),
        encoding="utf-8",
    )


def _build_domain_xml(plan: dict, overlay: Path, input_iso: Path) -> bytes:
    execution = plan["execution"]
    domain = ET.Element("domain", {"type": "kvm"})
    ET.SubElement(domain, "name").text = plan["job_id"]
    ET.SubElement(domain, "memory", {"unit": "MiB"}).text = str(execution["memory_mib"])
    ET.SubElement(domain, "vcpu", {"placement": "static"}).text = "1"
    os_node = ET.SubElement(domain, "os")
    ET.SubElement(
        os_node,
        "type",
        {"arch": "x86_64", "machine": "q35"},
    ).text = "hvm"
    ET.SubElement(os_node, "boot", {"dev": "hd"})
    features = ET.SubElement(domain, "features")
    ET.SubElement(features, "acpi")
    ET.SubElement(features, "apic")
    ET.SubElement(domain, "cpu", {"mode": "host-model", "check": "partial"})
    ET.SubElement(domain, "clock", {"offset": "utc"})
    ET.SubElement(domain, "on_poweroff").text = "destroy"
    ET.SubElement(domain, "on_reboot").text = "destroy"
    ET.SubElement(domain, "on_crash").text = "destroy"
    ET.SubElement(domain, "seclabel", {"type": "dynamic", "model": "selinux", "relabel": "yes"})
    devices = ET.SubElement(domain, "devices")

    disk = ET.SubElement(devices, "disk", {"type": "file", "device": "disk"})
    ET.SubElement(disk, "driver", {"name": "qemu", "type": "qcow2", "cache": "none"})
    ET.SubElement(disk, "source", {"file": str(overlay)})
    ET.SubElement(disk, "target", {"dev": "vda", "bus": "virtio"})
    cdrom = ET.SubElement(devices, "disk", {"type": "file", "device": "cdrom"})
    ET.SubElement(cdrom, "driver", {"name": "qemu", "type": "raw"})
    ET.SubElement(cdrom, "source", {"file": str(input_iso)})
    ET.SubElement(cdrom, "target", {"dev": "sda", "bus": "sata"})
    ET.SubElement(cdrom, "readonly")
    ET.SubElement(devices, "controller", {"type": "sata", "index": "0"})
    # Libvirt owns the pseudo-terminal. The runner captures it through the
    # libvirt console API, so QEMU receives no writable host-file endpoint.
    serial = ET.SubElement(devices, "serial", {"type": "pty"})
    ET.SubElement(serial, "target", {"type": "isa-serial", "port": "0"})
    ET.SubElement(devices, "video").append(ET.Element("model", {"type": "none"}))
    ET.SubElement(devices, "memballoon", {"model": "none"})
    return ET.tostring(domain, encoding="utf-8", xml_declaration=True)


def _extract_trace(serial_log: Path) -> bytes:
    payload = _bounded_regular_file(serial_log, MAX_TRACE_BYTES * 2)
    begin = TRACE_BEGIN.encode("ascii")
    end_marker = TRACE_END.encode("ascii")
    start = payload.rfind(begin)
    end = payload.find(end_marker, start + len(begin)) if start >= 0 else -1
    if start < 0 or end < 0:
        raise DynamicRunnerError("guest did not emit a complete runtime trace")
    # PTY boot output may contain arbitrary bytes and terminal escapes. Only
    # the marker-delimited payload is constrained to base64.
    encoded = b"".join(payload[start + len(begin) : end].split())
    try:
        trace = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DynamicRunnerError("guest runtime trace encoding is invalid") from exc
    if len(trace) > MAX_TRACE_BYTES:
        raise DynamicRunnerError("guest runtime trace exceeded 20 MiB")
    return trace


def _sign_trace(trace_path: Path, signing_key: Path) -> Path:
    if signing_key.is_symlink() or not signing_key.is_file():
        raise DynamicRunnerError("runtime signing key is unavailable or unsafe")
    signature = Path(str(trace_path) + ".sig")
    if signature.exists():
        raise DynamicRunnerError(f"signature output already exists: {signature}")
    _run_command([
        "ssh-keygen",
        "-Y",
        "sign",
        "-f",
        str(signing_key.resolve()),
        "-n",
        "waingro-runtime-v1",
        str(trace_path.resolve()),
    ], timeout=15)
    if not signature.is_file():
        raise DynamicRunnerError("ssh-keygen did not create the runtime signature")
    return signature


def run_dynamic_job(
    plan_path: Path,
    candidate: Path,
    *,
    confirm_job_id: str,
    image_dir: Path,
    work_root: Path,
    output_trace: Path,
    signing_key: Path | None = None,
) -> DynamicRunResult:
    """Execute one authorized plan in a transient hanna2 KVM guest."""
    plan = _load_plan(plan_path)
    job_id = plan["job_id"]
    if confirm_job_id != job_id:
        raise DynamicRunnerError("job confirmation does not match the authorized plan")
    _verify_host(work_root)
    if output_trace.exists():
        raise DynamicRunnerError(f"runtime trace output already exists: {output_trace}")
    if not candidate.is_dir() or candidate.is_symlink():
        raise DynamicRunnerError("candidate must be a non-symlink directory")
    static_result = scan_skill(candidate)
    artifact = static_result.artifact_identity
    if artifact is None or artifact.sha256 != plan["artifact"]["sha256"]:
        raise DynamicRunnerError("candidate artifact does not match the authorized plan")

    image_name = plan["execution"].get("base_image")
    if not isinstance(image_name, str) or Path(image_name).name != image_name:
        raise DynamicRunnerError("base image name violates policy")
    base_image = image_dir.resolve(strict=True) / image_name
    observed_base_digest = _bounded_regular_file(base_image).decode("ascii")
    if observed_base_digest != plan["execution"]["base_image_sha256"]:
        raise DynamicRunnerError("base image digest does not match the authorized plan")
    timed_out = False
    domain_started = False
    with tempfile.TemporaryDirectory(prefix=f"{job_id}-", dir=work_root) as temporary:
        job_dir = Path(temporary)
        job_dir.chmod(0o711)
        stage = job_dir / "input"
        _write_input_tree(stage, plan_path, candidate, plan)
        input_iso = job_dir / "input.iso"
        overlay = job_dir / "overlay.qcow2"
        serial_log = job_dir / "serial.log"
        domain_xml = job_dir / "domain.xml"
        _run_command([
            "xorriso", "-as", "mkisofs", "-quiet", "-V", "cidata",
            "-J", "-r", "-o", str(input_iso), str(stage),
        ], timeout=60)
        _run_command([
            "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2",
            "-b", str(base_image), str(overlay),
        ], timeout=30)
        domain_xml.write_bytes(_build_domain_xml(plan, overlay, input_iso))
        console_process = None
        console_output = None
        console_master = None
        try:
            _run_command([
                "virsh", "-c", "qemu:///system", "create", str(domain_xml), "--validate",
            ], timeout=30)
            domain_started = True
            virsh = shutil.which("virsh") or "/usr/bin/virsh"
            console_descriptor = os.open(
                serial_log,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            console_output = os.fdopen(console_descriptor, "wb")
            console_master, console_slave = pty.openpty()
            try:
                console_process = subprocess.Popen(  # noqa: S603 -- fixed libvirt console.
                    [
                        virsh,
                        "-c", "qemu:///system", "console", job_id, "--force",
                    ],
                    stdin=console_slave,
                    stdout=console_slave,
                    stderr=console_slave,
                    preexec_fn=_establish_controlling_tty,  # noqa: S606
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
                )
            finally:
                os.close(console_slave)
            deadline = time.monotonic() + plan["execution"]["timeout_seconds"] + 90
            console_bytes = 0
            console_closed = False
            while time.monotonic() < deadline:
                if not console_closed:
                    console_bytes, console_closed = _capture_console_chunk(
                        console_master,
                        console_output,
                        console_bytes,
                    )
                state = subprocess.run(  # noqa: S603 -- fixed virsh status query.
                    [
                        shutil.which("virsh") or "/usr/bin/virsh",
                        "-c", "qemu:///system", "domstate", job_id,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
                )
                if state.returncode != 0 or state.stdout.strip() in {"shut off", "crashed"}:
                    domain_started = False
                    for _ in range(4):
                        if console_closed:
                            break
                        console_bytes, console_closed = _capture_console_chunk(
                            console_master,
                            console_output,
                            console_bytes,
                        )
                    break
            else:
                timed_out = True
                _run_command([
                    "virsh", "-c", "qemu:///system", "destroy", job_id,
                ], timeout=20)
                domain_started = False
        finally:
            if domain_started:
                subprocess.run(  # noqa: S603 -- exact transient domain cleanup.
                    [
                        shutil.which("virsh") or "/usr/bin/virsh",
                        "-c", "qemu:///system", "destroy", job_id,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
                )
            if console_process is not None:
                try:
                    console_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    console_process.terminate()
                    try:
                        console_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        console_process.kill()
                        console_process.wait(timeout=5)
            if console_master is not None:
                os.close(console_master)
            if console_output is not None:
                console_output.flush()
                os.fsync(console_output.fileno())
                console_output.close()
        if timed_out:
            raise DynamicRunnerError("dynamic guest exceeded its total runtime limit")
        trace_payload = _extract_trace(serial_log)
        descriptor = os.open(output_trace, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            view = memoryview(trace_payload)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    loaded = load_runtime_trace(
        output_trace,
        expected_artifact_sha256=plan["artifact"]["sha256"],
        expected_base_image_sha256=plan["execution"]["base_image_sha256"],
    )
    if loaded.run_id != job_id:
        raise DynamicRunnerError("guest runtime trace has the wrong job id")
    signature_path = _sign_trace(output_trace, signing_key) if signing_key else None
    return DynamicRunResult(
        job_id=job_id,
        trace_path=str(output_trace),
        trace_sha256=loaded.trace_sha256,
        signature_path=str(signature_path) if signature_path else None,
        exit_status=loaded.exit_status,
        event_count=len(loaded.events),
        timed_out=False,
    )
