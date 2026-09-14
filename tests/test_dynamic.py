"""Tests for fail-closed dynamic plans and runtime trace ingestion."""

import base64
import hashlib
import json
import os
import socket
import ssl
import stat
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from waingro.dynamic import guest_agent_payload
from waingro.dynamic.guest_agent_payload import (
    _connect_event_type,
    _dns_name,
    _use_direct_loopback_dns,
)
from waingro.dynamic.host import HostPolicy
from waingro.dynamic.plan import build_dynamic_plan, dynamic_job_id, write_plan
from waingro.dynamic.runner import (
    DynamicRunnerError,
    _allocated_bytes,
    _build_domain_xml,
    _extract_trace,
    _load_plan,
    _verify_base_capabilities,
)
from waingro.dynamic.trace import (
    RuntimeTraceError,
    load_runtime_trace,
    verify_trace_signature,
)
from waingro.models import ArtifactFileDigest, ArtifactIdentity
from waingro.scanner import scan_skill

FIXTURES = Path(__file__).parent / "fixtures"
HOST_POLICY_DIGEST = "d" * 64


def _identity(records: list[ArtifactFileDigest]) -> ArtifactIdentity:
    digest = hashlib.sha256()
    for record in sorted(records, key=lambda item: item.path):
        path = record.path.encode()
        digest.update(len(path).to_bytes(8, "big"))
        digest.update(path)
        digest.update(record.size_bytes.to_bytes(8, "big"))
        digest.update(bytes.fromhex(record.sha256))
    return ArtifactIdentity(
        sha256=digest.hexdigest(),
        file_count=len(records),
        total_bytes=sum(record.size_bytes for record in records),
        files=records,
    )


def _artifact() -> ArtifactIdentity:
    return _identity([ArtifactFileDigest("SKILL.md", "b" * 64, 10)])


def _script_artifact() -> ArtifactIdentity:
    return _identity(
        [
            ArtifactFileDigest("SKILL.md", "b" * 64, 10),
            ArtifactFileDigest("scripts/run.py", "c" * 64, 10),
        ]
    )


def _trace() -> dict:
    return {
        "schema_version": "1.0",
        "run_id": "waingro-test",
        "artifact_sha256": "a" * 64,
        "host": "hanna2",
        "backend": "libvirt-kvm",
        "started_at": "2026-09-11T12:00:00Z",
        "finished_at": "2026-09-11T12:01:00Z",
        "exit_status": "completed",
        "isolation": {
            "hypervisor": "libvirt-kvm",
            "hardware_virtualization": True,
            "ephemeral_disk": True,
            "host_shares": False,
            "host_credentials": False,
            "network_policy": "none",
            "base_image_sha256": "b" * 64,
            "candidate_read_only": True,
        },
        "events": [
            {
                "type": "process",
                "action": "exec",
                "timestamp": "2026-09-11T12:00:01Z",
                "process_id": 10,
                "command": "synthetic command",
            }
        ],
    }


def test_guest_trace_records_parent_processes(tmp_path, monkeypatch):
    monkeypatch.setattr(guest_agent_payload, "TRACE_DIR", tmp_path)
    (tmp_path / "strace.100").write_text(
        "1789142400.000000 clone(child_stack=NULL, flags=SIGCHLD) = 101\n",
        encoding="utf-8",
    )
    (tmp_path / "strace.101").write_text(
        '1789142400.100000 execve("/usr/bin/bash", ["bash"], []) = 0\n'
        '1789142400.200000 openat(AT_FDCWD, "/home/waingro/.aws/credentials", '
        "O_RDONLY) = 3\n"
        "1789142400.300000 connect(4, {sa_family=AF_INET, "
        "sin_port=htons(443)}, 16) = -1 ENETUNREACH\n",
        encoding="utf-8",
    )

    events = guest_agent_payload._parse_events()

    assert len(events) == 3
    assert {event["parent_process_id"] for event in events} == {100}
    assert {event["process_id"] for event in events} == {101}


def test_dynamic_plan_is_fail_closed_and_artifact_bound(tmp_path):
    plan = build_dynamic_plan(
        _artifact(),
        base_image="waingro-base.qcow2",
        base_image_sha256="c" * 64,
    )

    data = plan.to_dict()
    assert data["execution"]["authorized"] is False
    assert data["execution"]["host_shares"] is False
    assert data["execution"]["network_policy"] == "none"
    assert data["artifact"]["sha256"] == _artifact().sha256
    output = tmp_path / "plan.json"
    write_plan(plan, output)
    with pytest.raises(FileExistsError):
        write_plan(plan, output)


@pytest.mark.parametrize(
    ("image", "network"),
    [("../base.qcow2", "none"), ("base.img", "none"), ("base.qcow2", "internet")],
)
def test_dynamic_plan_rejects_unsafe_inputs(image, network):
    with pytest.raises(ValueError):
        build_dynamic_plan(
            _artifact(),
            base_image=image,
            base_image_sha256="c" * 64,
            network_policy=network,
        )


def test_authorized_dynamic_plan_requires_scanned_typed_entrypoint():
    plan = build_dynamic_plan(
        _script_artifact(),
        base_image="waingro-base.qcow2",
        base_image_sha256="c" * 64,
        host_policy_sha256=HOST_POLICY_DIGEST,
        authorize_execution=True,
        interpreter="python",
        entrypoint="scripts/run.py",
        arguments=("--safe-fixture",),
        required_event_types=("process",),
    )

    assert plan.execution_authorized is True
    assert plan.to_dict()["execution"]["scenario"]["arguments"] == ["--safe-fixture"]
    assert plan.required_executables == ("python3",)
    with pytest.raises(ValueError, match="not in the scanned artifact"):
        build_dynamic_plan(
            _script_artifact(),
            base_image="waingro-base.qcow2",
            base_image_sha256="c" * 64,
            host_policy_sha256=HOST_POLICY_DIGEST,
            authorize_execution=True,
            interpreter="python",
            entrypoint="scripts/missing.py",
            required_event_types=("process",),
        )


def test_dynamic_plan_binds_prerequisites_canaries_and_coverage():
    plan = build_dynamic_plan(
        _script_artifact(),
        base_image="waingro-base.qcow2",
        base_image_sha256="c" * 64,
        host_policy_sha256=HOST_POLICY_DIGEST,
        authorize_execution=True,
        interpreter="python",
        entrypoint="scripts/run.py",
        required_executables=("curl",),
        synthetic_environment=(("SERVICE_TOKEN", "token"),),
        required_event_types=("credential", "network"),
        require_exit_zero=True,
    )

    scenario = plan.to_dict()["execution"]["scenario"]
    assert scenario["required_executables"] == ["curl", "python3"]
    assert scenario["synthetic_environment"] == {"SERVICE_TOKEN": "token"}
    assert scenario["coverage"] == {
        "required_event_types": ["credential", "network"],
        "require_exit_zero": True,
    }


def test_dynamic_plan_requires_policy_and_a_separate_corpus_gate():
    with pytest.raises(ValueError, match="host policy"):
        build_dynamic_plan(
            _script_artifact(),
            base_image="waingro-base.qcow2",
            base_image_sha256="c" * 64,
            authorize_execution=True,
            interpreter="python",
            entrypoint="scripts/run.py",
            required_event_types=("process",),
        )
    with pytest.raises(ValueError, match="separate explicit authorization"):
        build_dynamic_plan(
            _script_artifact(),
            base_image="waingro-base.qcow2",
            base_image_sha256="c" * 64,
            host_policy_sha256=HOST_POLICY_DIGEST,
            specimen_class="corpus",
            authorize_execution=True,
            interpreter="python",
            entrypoint="scripts/run.py",
            required_event_types=("process",),
        )
    plan = build_dynamic_plan(
        _script_artifact(),
        base_image="waingro-base.qcow2",
        base_image_sha256="c" * 64,
        host_policy_sha256=HOST_POLICY_DIGEST,
        campaign_id="clawhub-2026-09",
        specimen_class="corpus",
        authorize_corpus=True,
        authorize_execution=True,
        interpreter="python",
        entrypoint="scripts/run.py",
        required_event_types=("process",),
    )
    assert plan.schema_version == "1.3"
    assert plan.corpus_authorized is True


def test_fixture_policy_never_authorizes_a_corpus_artifact():
    policy = HostPolicy(
        host="hanna2",
        runner_user="waingro-runner",
        dedicated=True,
        corpus_execution_enabled=False,
        campaign_id="fixture-validation",
        allowed_artifact_sha256=(),
        allowed_network_policies=("none", "loopback-sinkhole"),
        egress_marker=Path("/run/waingro/egress-locked"),
        policy_sha256=HOST_POLICY_DIGEST,
    )

    assert policy.authorizes("fixture", "a" * 64, "fixture-validation") is True
    assert policy.authorizes("corpus", "a" * 64, "fixture-validation") is False


def test_authorized_dynamic_plan_requires_explicit_coverage():
    with pytest.raises(ValueError, match="coverage event"):
        build_dynamic_plan(
            _script_artifact(),
            base_image="waingro-base.qcow2",
            base_image_sha256="c" * 64,
            host_policy_sha256=HOST_POLICY_DIGEST,
            authorize_execution=True,
            interpreter="python",
            entrypoint="scripts/run.py",
        )

    with pytest.raises(ValueError, match="synthetic environment"):
        build_dynamic_plan(
            _script_artifact(),
            base_image="waingro-base.qcow2",
            base_image_sha256="c" * 64,
            interpreter="python",
            entrypoint="scripts/run.py",
            synthetic_environment=(("PYTHONPATH", "token"),),
        )


def test_base_capability_manifest_is_digest_bound_and_fail_closed(tmp_path):
    image = tmp_path / "base.qcow2"
    image.write_bytes(b"pinned image")
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    manifest = image.with_suffix(".qcow2.capabilities.json")
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "base_image_sha256": digest,
                "executables": ["bash", "python3"],
            }
        ),
        encoding="utf-8",
    )

    _verify_base_capabilities(image, digest, ["python3"])
    with pytest.raises(DynamicRunnerError, match="lacks required"):
        _verify_base_capabilities(image, digest, ["node"])
    manifest.unlink()
    with pytest.raises(DynamicRunnerError, match="missing or invalid"):
        _verify_base_capabilities(image, digest, ["python3"])


def test_runtime_trace_validates_explicit_coverage(tmp_path):
    raw = _trace()
    raw["schema_version"] = "1.1"
    raw["exit_status"] = "exit-0"
    raw["coverage"] = {
        "required_event_types": ["process", "network"],
        "observed_event_types": ["process"],
        "missing_event_types": ["network"],
        "require_exit_zero": True,
        "exit_status_satisfied": True,
        "complete": False,
    }
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    trace = load_runtime_trace(path, expected_artifact_sha256="a" * 64)
    assert trace.coverage is not None
    assert trace.coverage.complete is False
    raw["coverage"]["complete"] = True
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(RuntimeTraceError, match="do not match observations"):
        load_runtime_trace(path, expected_artifact_sha256="a" * 64)


def test_runtime_trace_never_counts_timeout_as_complete_coverage(tmp_path):
    raw = _trace()
    raw["schema_version"] = "1.1"
    raw["exit_status"] = "timeout"
    raw["coverage"] = {
        "required_event_types": ["process"],
        "observed_event_types": ["process"],
        "missing_event_types": [],
        "require_exit_zero": False,
        "exit_status_satisfied": False,
        "complete": False,
    }
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    trace = load_runtime_trace(path, expected_artifact_sha256="a" * 64)
    assert trace.coverage is not None
    assert trace.coverage.complete is False


def test_runtime_trace_v12_binds_host_policy_and_rejects_an_external_interface(
    tmp_path,
):
    raw = _trace()
    raw["schema_version"] = "1.2"
    raw["exit_status"] = "exit-0"
    raw["isolation"]["external_network_interfaces"] = []
    raw["isolation"]["sinkhole_local"] = False
    raw["coverage"] = {
        "required_event_types": ["process"],
        "observed_event_types": ["process"],
        "missing_event_types": [],
        "require_exit_zero": True,
        "exit_status_satisfied": True,
        "complete": True,
    }
    raw["harness"] = {
        "campaign_id": "fixture-validation",
        "specimen_class": "fixture",
        "host_policy_sha256": HOST_POLICY_DIGEST,
    }
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    trace = load_runtime_trace(
        path,
        expected_artifact_sha256="a" * 64,
        expected_host_policy_sha256=HOST_POLICY_DIGEST,
    )
    assert trace.host_policy_verified is True
    assert trace.isolation.valid is True

    raw["isolation"]["external_network_interfaces"] = ["ens3"]
    path.write_text(json.dumps(raw), encoding="utf-8")
    trace = load_runtime_trace(
        path,
        expected_artifact_sha256="a" * 64,
        expected_host_policy_sha256=HOST_POLICY_DIGEST,
    )
    assert trace.isolation.valid is False


def test_runtime_trace_binds_to_artifact_and_is_untrusted_without_signature(tmp_path):
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(_trace()), encoding="utf-8")

    trace = load_runtime_trace(path, expected_artifact_sha256="a" * 64)

    assert trace.artifact_sha256 == "a" * 64
    assert trace.trusted is False
    assert "runtime trace is not authenticated" in trace.warnings


def test_runtime_trace_rejects_artifact_mismatch(tmp_path):
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(_trace()), encoding="utf-8")

    with pytest.raises(RuntimeTraceError, match="does not match"):
        load_runtime_trace(path, expected_artifact_sha256="f" * 64)


def test_runtime_trace_rejects_invalid_isolation_as_trusted(tmp_path, monkeypatch):
    raw = _trace()
    raw["isolation"]["host_shares"] = True
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    signature = tmp_path / "trace.sig"
    signature.write_text("signature", encoding="utf-8")
    signers = tmp_path / "allowed_signers"
    signers.write_text("hanna2 ssh-ed25519 AAAA", encoding="utf-8")
    monkeypatch.setattr(
        "waingro.dynamic.trace.verify_trace_signature",
        lambda *_args, **_kwargs: True,
    )

    trace = load_runtime_trace(
        path,
        expected_artifact_sha256="a" * 64,
        signature_path=signature,
        allowed_signers=signers,
    )

    assert trace.signature_verified is True
    assert trace.isolation.valid is False
    assert trace.trusted is False


def test_runtime_trace_rejects_symlink(tmp_path):
    target = tmp_path / "target.json"
    target.write_text(json.dumps(_trace()), encoding="utf-8")
    link = tmp_path / "trace.json"
    link.symlink_to(target)

    with pytest.raises(RuntimeTraceError, match="symlinks"):
        load_runtime_trace(link, expected_artifact_sha256="a" * 64)


def test_runtime_signature_verification_rejects_symlink_inputs(tmp_path):
    signature = tmp_path / "trace.sig"
    signature.write_text("signature", encoding="utf-8")
    signature_link = tmp_path / "trace-link.sig"
    signature_link.symlink_to(signature)
    signers = tmp_path / "allowed_signers"
    signers.write_text("hanna2 ssh-ed25519 AAAA", encoding="utf-8")

    with pytest.raises(RuntimeTraceError, match="symlinks"):
        verify_trace_signature(b"trace", signature_link, signers)


def test_runtime_trace_rejects_event_outside_run_interval(tmp_path):
    raw = _trace()
    raw["events"][0]["timestamp"] = "2026-09-11T11:59:59Z"
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(RuntimeTraceError, match="outside the trace interval"):
        load_runtime_trace(path, expected_artifact_sha256="a" * 64)


def test_signed_runtime_trace_requires_approved_base_image(tmp_path, monkeypatch):
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(_trace()), encoding="utf-8")
    signature = tmp_path / "trace.sig"
    signature.write_text("signature", encoding="utf-8")
    signers = tmp_path / "allowed_signers"
    signers.write_text("hanna2 ssh-ed25519 AAAA", encoding="utf-8")
    monkeypatch.setattr(
        "waingro.dynamic.trace.verify_trace_signature",
        lambda *_args, **_kwargs: True,
    )

    unbound = load_runtime_trace(
        path,
        expected_artifact_sha256="a" * 64,
        signature_path=signature,
        allowed_signers=signers,
    )
    assert unbound.signature_verified is True
    assert unbound.base_image_verified is False
    assert unbound.trusted is False

    bound = load_runtime_trace(
        path,
        expected_artifact_sha256="a" * 64,
        signature_path=signature,
        allowed_signers=signers,
        expected_base_image_sha256="b" * 64,
    )
    assert bound.base_image_verified is True
    assert bound.trusted is True

    with pytest.raises(RuntimeTraceError, match="approved image"):
        load_runtime_trace(
            path,
            expected_artifact_sha256="a" * 64,
            expected_base_image_sha256="c" * 64,
        )


def test_runner_plan_loader_and_domain_xml_have_no_host_share_or_default_network(tmp_path):
    plan = build_dynamic_plan(
        _script_artifact(),
        base_image="waingro-base.qcow2",
        base_image_sha256="c" * 64,
        host_policy_sha256=HOST_POLICY_DIGEST,
        authorize_execution=True,
        interpreter="python",
        entrypoint="scripts/run.py",
        required_event_types=("process",),
    )
    plan_path = tmp_path / "plan.json"
    write_plan(plan, plan_path)

    loaded = _load_plan(plan_path)
    xml = _build_domain_xml(
        loaded,
        tmp_path / "overlay.qcow2",
        tmp_path / "input.iso",
        tmp_path / "waingro-base.qcow2",
    ).decode()

    assert 'type="kvm"' in xml
    assert "<filesystem" not in xml
    assert "<hostdev" not in xml
    assert "<interface" not in xml
    assert "<readonly" in xml
    assert 'model="selinux"' in xml
    assert '<serial type="pty"' in xml
    assert 'device="cdrom"' not in xml
    assert 'dev="vdb" bus="virtio"' in xml
    assert 'model="none"' in xml
    assert '<backingStore type="file">' in xml
    assert f'file="{tmp_path / "waingro-base.qcow2"}"' in xml
    assert '<seclabel model="selinux" relabel="no"' in xml
    assert '<seclabel model="dac" relabel="no"' in xml
    assert "qemu:commandline" in xml
    assert "elevateprivileges=deny" in xml


def test_sparse_overlay_limit_uses_allocated_blocks(tmp_path):
    overlay = tmp_path / "overlay.qcow2"
    with overlay.open("wb") as handle:
        handle.truncate(8 * 1024 * 1024 * 1024)

    assert _allocated_bytes(overlay) < overlay.stat().st_size


def test_runner_plan_loader_rejects_tampered_artifact_inventory(tmp_path):
    plan = build_dynamic_plan(
        _script_artifact(),
        base_image="waingro-base.qcow2",
        base_image_sha256="c" * 64,
        host_policy_sha256=HOST_POLICY_DIGEST,
        authorize_execution=True,
        interpreter="python",
        entrypoint="scripts/run.py",
        required_event_types=("process",),
    ).to_dict()
    plan["artifact"]["total_bytes"] += 1
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")

    with pytest.raises(DynamicRunnerError, match="changed after its job id"):
        _load_plan(plan_path)


def test_runner_extracts_bounded_guest_trace(tmp_path):
    raw = json.dumps(_trace()).encode()
    encoded = base64.b64encode(raw).decode()
    serial = tmp_path / "serial.log"
    serial.write_bytes(
        b"boot noise \xff\nWAINGRO_TRACE_BEGIN\n" + encoded.encode() + b"\nWAINGRO_TRACE_END\n"
    )

    assert _extract_trace(serial) == raw

    serial.write_text("no trace", encoding="ascii")
    with pytest.raises(DynamicRunnerError, match="complete runtime trace"):
        _extract_trace(serial)


def test_benign_runtime_fixture_produces_an_authorized_plan():
    result = scan_skill(FIXTURES / "dynamic" / "benign-runtime")

    plan = build_dynamic_plan(
        result.artifact_identity,
        base_image="waingro-fedora43.qcow2",
        base_image_sha256="c" * 64,
        host_policy_sha256=HOST_POLICY_DIGEST,
        authorize_execution=True,
        interpreter="python",
        entrypoint="scripts/run.py",
        required_event_types=("process",),
    )

    assert plan.artifact_sha256 == result.artifact_identity.sha256
    assert plan.execution_authorized is True


def test_adversarial_runtime_fixture_produces_an_artifact_bound_plan():
    result = scan_skill(FIXTURES / "dynamic" / "adversarial-runtime")

    plan = build_dynamic_plan(
        result.artifact_identity,
        base_image="waingro-fedora43.qcow2",
        base_image_sha256="c" * 64,
        host_policy_sha256=HOST_POLICY_DIGEST,
        network_policy="none",
        authorize_execution=True,
        interpreter="python",
        entrypoint="scripts/run.py",
        required_event_types=("credential", "network"),
    )

    assert plan.artifact_sha256 == result.artifact_identity.sha256
    assert plan.network_policy == "none"


def test_guest_telemetry_ignores_local_ipc_and_identifies_dns():
    assert _connect_event_type('connect(3, {sa_family=AF_UNIX, sun_path="/dev/log"})') is None
    assert _connect_event_type("connect(3, {sa_family=AF_INET, sin_port=htons(443)})") == "network"
    assert _connect_event_type("connect(3, {sa_family=AF_INET6, sin6_port=htons(53)})") == "dns"


def test_loopback_sinkhole_dns_parser_extracts_only_a_bounded_query():
    query = (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    )

    assert _dns_name(query) == ("example.com", 1, len(query))
    assert _dns_name(b"short") is None


def test_loopback_sinkhole_forces_direct_guest_dns(tmp_path):
    nsswitch = tmp_path / "nsswitch.conf"
    resolver = tmp_path / "resolv.conf"
    nsswitch.write_text(
        "passwd: files\nhosts: myhostname resolve [!UNAVAIL=return] files dns\n",
        encoding="utf-8",
    )
    resolver.write_text("nameserver 192.0.2.1\n", encoding="ascii")

    _use_direct_loopback_dns(nsswitch, resolver)

    assert "hosts: files dns\n" in nsswitch.read_text(encoding="utf-8")
    assert resolver.read_text(encoding="ascii") == (
        "nameserver 127.0.0.1\noptions attempts:1 timeout:1\n"
    )


def test_loopback_sinkhole_rejects_ambiguous_guest_dns_policy(tmp_path):
    nsswitch = tmp_path / "nsswitch.conf"
    resolver = tmp_path / "resolv.conf"
    nsswitch.write_text("hosts: files\nhosts: dns\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="unavailable or ambiguous"):
        _use_direct_loopback_dns(nsswitch, resolver)


def test_dynamic_plan_binds_containment_profile_bytes_and_controls():
    response = b'{"status":"synthetic"}\n'
    configuration = b'{"api_key":"WAINGRO_CANARY","api_base":"https://fixture.invalid"}\n'

    plan = build_dynamic_plan(
        _script_artifact(),
        base_image="waingro-base.qcow2",
        base_image_sha256="c" * 64,
        host_policy_sha256=HOST_POLICY_DIGEST,
        network_policy="loopback-sinkhole",
        authorize_execution=True,
        interpreter="python",
        entrypoint="scripts/run.py",
        openclaw_skill_slug="benign-control",
        inert_command_shims=("openclaw", "crontab"),
        sinkhole_http_host="fixture.invalid",
        sinkhole_http_method="POST",
        sinkhole_http_path="/api/heartbeat",
        sinkhole_http_body=response,
        synthetic_json_files=((".benign/config.json", configuration),),
        required_event_types=("process", "network"),
    )

    containment = plan.to_dict()["execution"]["containment"]
    sinkhole = containment["sinkhole_http_response"]
    assert plan.schema_version == "1.3"
    assert containment["openclaw_skill_slug"] == "benign-control"
    assert containment["inert_command_shims"] == ["openclaw", "crontab"]
    assert sinkhole["sha256"] == hashlib.sha256(response).hexdigest()
    assert base64.b64decode(sinkhole["body_base64"]) == response
    assert base64.b64decode(containment["synthetic_json_files"][0]["body_base64"]) == configuration
    assert "openssl" in plan.required_executables


@pytest.mark.parametrize(
    "overrides",
    [
        {"sinkhole_http_host": "fixture.invalid"},
        {
            "sinkhole_http_host": "127.0.0.1",
            "sinkhole_http_method": "POST",
            "sinkhole_http_path": "/fixture",
            "sinkhole_http_body": b"{}",
            "network_policy": "loopback-sinkhole",
        },
        {
            "sinkhole_http_host": "fixture.invalid",
            "sinkhole_http_method": "POST",
            "sinkhole_http_path": "/fixture",
            "sinkhole_http_body": b"not-json",
            "network_policy": "loopback-sinkhole",
        },
        {
            "sinkhole_http_host": "fixture.invalid",
            "sinkhole_http_method": "post",
            "sinkhole_http_path": "/fixture",
            "sinkhole_http_body": b"{}",
            "network_policy": "loopback-sinkhole",
        },
        {"synthetic_json_files": (("../escape.json", b"{}"),)},
        {"inert_command_shims": ("openclaw", "openclaw")},
        {
            "inert_command_shims": ("openclaw",),
            "required_executables": ("openclaw",),
        },
    ],
)
def test_dynamic_plan_rejects_invalid_containment_profiles(overrides):
    arguments = {
        "base_image": "waingro-base.qcow2",
        "base_image_sha256": "c" * 64,
        "host_policy_sha256": HOST_POLICY_DIGEST,
        "interpreter": "python",
        "entrypoint": "scripts/run.py",
    }
    arguments.update(overrides)

    with pytest.raises(ValueError):
        build_dynamic_plan(_script_artifact(), **arguments)


def test_runner_revalidates_embedded_response_identity(tmp_path):
    plan = build_dynamic_plan(
        _script_artifact(),
        base_image="waingro-base.qcow2",
        base_image_sha256="c" * 64,
        host_policy_sha256=HOST_POLICY_DIGEST,
        network_policy="loopback-sinkhole",
        authorize_execution=True,
        interpreter="python",
        entrypoint="scripts/run.py",
        sinkhole_http_host="fixture.invalid",
        sinkhole_http_method="POST",
        sinkhole_http_path="/fixture",
        sinkhole_http_body=b'{"status":"synthetic"}',
        required_event_types=("network",),
    ).to_dict()
    plan["execution"]["containment"]["sinkhole_http_response"]["body_base64"] = base64.b64encode(
        b'{"status":"changed"}'
    ).decode("ascii")
    plan["job_id"] = dynamic_job_id(plan)
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")

    with pytest.raises(DynamicRunnerError, match="identity"):
        _load_plan(path)


def test_inert_shims_are_no_op_and_precede_guest_path(tmp_path, monkeypatch):
    shim_dir = tmp_path / "shims"
    monkeypatch.setattr(guest_agent_payload, "SHIM_DIR", shim_dir)
    monkeypatch.setattr(guest_agent_payload.os, "chown", lambda *_args: None)
    plan = {"execution": {"containment": {"inert_command_shims": ["openclaw", "crontab"]}}}
    environment = {"PATH": "/usr/bin:/bin"}

    guest_agent_payload._install_inert_shims(plan, environment)

    assert environment["PATH"].split(":", 1)[0] == str(shim_dir)
    for name in ("openclaw", "crontab"):
        result = subprocess.run(  # noqa: S603 -- executes only the generated inert test shim.
            ["/bin/bash", str(shim_dir / name), "ignored"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
        assert result.stdout == f"WAINGRO_INERT_SHIM:{name}\n"


def test_openclaw_layout_is_an_immutable_alias_to_candidate(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    monkeypatch.setattr(guest_agent_payload, "CANDIDATE", candidate)
    monkeypatch.setattr(guest_agent_payload.os, "chown", lambda *_args: None)
    plan = {"execution": {"containment": {"openclaw_skill_slug": "benign-control"}}}

    guest_agent_payload._stage_openclaw_layout(plan, home)

    link = home / ".openclaw" / "workspace" / "skills" / "benign-control"
    assert link.is_symlink()
    assert link.resolve() == candidate.resolve()
    assert (link.parent.stat().st_mode & 0o777) == 0o555


def test_synthetic_json_is_digest_checked_and_bound_read_only(tmp_path, monkeypatch):
    body = b'{"status":"synthetic"}'
    record = {
        "home_path": ".benign/config.json",
        "sha256": hashlib.sha256(body).hexdigest(),
        "size_bytes": len(body),
        "body_base64": base64.b64encode(body).decode("ascii"),
    }
    home = tmp_path / "home"
    home.mkdir()
    fixture_dir = tmp_path / "fixtures"
    mounted = []
    monkeypatch.setattr(guest_agent_payload, "FIXTURE_DIR", fixture_dir)
    monkeypatch.setattr(
        guest_agent_payload.pwd,
        "getpwnam",
        lambda _name: SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()),
    )
    monkeypatch.setattr(guest_agent_payload.os, "chown", lambda *_args: None)
    monkeypatch.setattr(
        guest_agent_payload,
        "_bind_read_only",
        lambda source, target: mounted.append((source, target)),
    )
    plan = {"execution": {"containment": {"synthetic_json_files": [record]}}}

    guest_agent_payload._stage_synthetic_json(plan, home)

    assert (fixture_dir / "0.json").read_bytes() == body
    assert (fixture_dir / "0.json").stat().st_mode & 0o777 == 0o444
    assert mounted == [(fixture_dir / "0.json", home / ".benign" / "config.json")]


def test_fixed_response_https_sinkhole_is_local_and_route_exact(tmp_path):
    host = "fixture.invalid"
    body = b'{"status":"synthetic"}'
    response = {
        "host": host,
        "method": "POST",
        "path": "/api/heartbeat",
        "sha256": hashlib.sha256(body).hexdigest(),
        "size_bytes": len(body),
        "body_base64": base64.b64encode(body).decode("ascii"),
    }
    tls_dir = tmp_path / "tls"
    tls_context, certificate = guest_agent_payload._create_tls_context(host, tls_dir)
    assert stat.S_IMODE(tls_dir.stat().st_mode) == 0o711
    assert stat.S_IMODE((tls_dir / "server.key").stat().st_mode) == 0o400
    assert stat.S_IMODE(certificate.stat().st_mode) == 0o444
    server_socket, client_socket = socket.socketpair()

    class OneConnectionServer:
        accepted = False

        def accept(self):
            if self.accepted:
                raise OSError("closed")
            self.accepted = True
            return server_socket, None

    thread = threading.Thread(
        target=guest_agent_payload._http_sinkhole,
        args=(OneConnectionServer(),),
        kwargs={"tls": True, "tls_context": tls_context, "response": response},
        daemon=True,
    )
    thread.start()
    client_context = ssl.create_default_context(cafile=str(certificate))
    with client_context.wrap_socket(client_socket, server_hostname=host) as client:
        client.sendall(
            b"POST /api/heartbeat HTTP/1.1\r\nHost: fixture.invalid\r\nContent-Length: 0\r\n\r\n"
        )
        reply = client.recv(4096)
    thread.join(timeout=2)

    assert b"HTTP/1.1 200 OK" in reply
    assert reply.endswith(body)


def test_fixed_response_sinkhole_rejects_an_unplanned_method():
    body = b'{"status":"synthetic"}'
    response = {
        "host": "fixture.invalid",
        "method": "POST",
        "path": "/api/heartbeat",
        "sha256": hashlib.sha256(body).hexdigest(),
        "size_bytes": len(body),
        "body_base64": base64.b64encode(body).decode("ascii"),
    }
    server_socket, client_socket = socket.socketpair()

    class OneConnectionServer:
        accepted = False

        def accept(self):
            if self.accepted:
                raise OSError("closed")
            self.accepted = True
            return server_socket, None

    thread = threading.Thread(
        target=guest_agent_payload._http_sinkhole,
        args=(OneConnectionServer(),),
        kwargs={"response": response},
        daemon=True,
    )
    thread.start()
    with client_socket:
        client_socket.sendall(b"GET /api/heartbeat HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n")
        reply = client_socket.recv(4096)

    thread.join(timeout=2)
    assert b"404 Not Found" in reply
    assert not reply.endswith(body)


def test_fixed_response_https_sinkhole_rejects_unplanned_sni(tmp_path):
    host = "fixture.invalid"
    tls_context, certificate = guest_agent_payload._create_tls_context(host, tmp_path / "tls")
    server_socket, client_socket = socket.socketpair()

    class OneConnectionServer:
        accepted = False

        def accept(self):
            if self.accepted:
                raise OSError("closed")
            self.accepted = True
            return server_socket, None

    thread = threading.Thread(
        target=guest_agent_payload._http_sinkhole,
        args=(OneConnectionServer(),),
        kwargs={"tls": True, "tls_context": tls_context},
        daemon=True,
    )
    thread.start()
    client_context = ssl.create_default_context(cafile=str(certificate))

    with (
        client_socket,
        pytest.raises(ssl.SSLError),
        client_context.wrap_socket(client_socket, server_hostname="other.invalid"),
    ):
        pass
    thread.join(timeout=2)
