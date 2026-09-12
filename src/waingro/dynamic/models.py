"""Strict models for isolated runtime observations."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class RuntimeEventType(StrEnum):
    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"
    DNS = "dns"
    PERSISTENCE = "persistence"
    CREDENTIAL = "credential"
    DEFENSE_EVASION = "defense-evasion"
    HARNESS = "harness"


@dataclass(frozen=True)
class RuntimeEvent:
    event_type: RuntimeEventType
    action: str
    timestamp: str
    process_id: int | None = None
    parent_process_id: int | None = None
    process: str | None = None
    target: str | None = None
    destination: str | None = None
    command: str | None = None
    success: bool | None = None
    labels: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "type": self.event_type.value,
            "action": self.action,
            "timestamp": self.timestamp,
            "process_id": self.process_id,
            "parent_process_id": self.parent_process_id,
            "process": self.process,
            "target": self.target,
            "destination": self.destination,
            "command": self.command,
            "success": self.success,
            "labels": list(self.labels),
        }


@dataclass(frozen=True)
class IsolationRecord:
    hypervisor: str
    hardware_virtualization: bool
    ephemeral_disk: bool
    host_shares: bool
    host_credentials: bool
    network_policy: str
    base_image_sha256: str
    candidate_read_only: bool

    @property
    def valid(self) -> bool:
        return (
            self.hypervisor in {"kvm", "libvirt-kvm"}
            and self.hardware_virtualization
            and self.ephemeral_disk
            and not self.host_shares
            and not self.host_credentials
            and self.network_policy == "none"
            and self.candidate_read_only
            and len(self.base_image_sha256) == 64
        )

    def to_dict(self) -> dict:
        return {
            "hypervisor": self.hypervisor,
            "hardware_virtualization": self.hardware_virtualization,
            "ephemeral_disk": self.ephemeral_disk,
            "host_shares": self.host_shares,
            "host_credentials": self.host_credentials,
            "network_policy": self.network_policy,
            "base_image_sha256": self.base_image_sha256,
            "candidate_read_only": self.candidate_read_only,
            "valid": self.valid,
        }


@dataclass(frozen=True)
class RuntimeTrace:
    run_id: str
    artifact_sha256: str
    host: str
    backend: str
    started_at: str
    finished_at: str
    exit_status: str
    isolation: IsolationRecord
    events: tuple[RuntimeEvent, ...]
    trace_sha256: str
    signature_verified: bool = False
    signature_identity: str | None = None
    base_image_verified: bool = False
    warnings: tuple[str, ...] = field(default_factory=tuple)
    schema_version: str = "1.0"

    @property
    def trusted(self) -> bool:
        return (
            self.signature_verified
            and self.signature_identity == self.host
            and self.base_image_verified
            and self.host == "hanna2"
            and self.backend == "libvirt-kvm"
            and self.isolation.valid
        )

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "artifact_sha256": self.artifact_sha256,
            "host": self.host,
            "backend": self.backend,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "exit_status": self.exit_status,
            "isolation": self.isolation.to_dict(),
            "events": [event.to_dict() for event in self.events],
            "trace_sha256": self.trace_sha256,
            "signature_verified": self.signature_verified,
            "signature_identity": self.signature_identity,
            "base_image_verified": self.base_image_verified,
            "trusted": self.trusted,
            "warnings": list(self.warnings),
        }
