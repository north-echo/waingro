"""Turn validated runtime events into evidence and attack paths."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from waingro.dynamic.models import RuntimeEvent, RuntimeEventType, RuntimeTrace
from waingro.evidence import (
    AttackPath,
    EvidenceItem,
    EvidencePolarity,
    EvidenceSource,
)
from waingro.ttps import techniques_for_runtime_stage

_TYPE_STAGE = {
    RuntimeEventType.PROCESS: "execution",
    RuntimeEventType.FILE: "file-access",
    RuntimeEventType.NETWORK: "network",
    RuntimeEventType.DNS: "network",
    RuntimeEventType.PERSISTENCE: "persistence",
    RuntimeEventType.CREDENTIAL: "credential-access",
    RuntimeEventType.DEFENSE_EVASION: "evasion",
}

_EVENT_STRENGTH = {
    RuntimeEventType.PROCESS: 0.45,
    RuntimeEventType.FILE: 0.3,
    RuntimeEventType.NETWORK: 0.55,
    RuntimeEventType.DNS: 0.5,
    RuntimeEventType.PERSISTENCE: 0.85,
    RuntimeEventType.CREDENTIAL: 0.9,
    RuntimeEventType.DEFENSE_EVASION: 0.85,
    RuntimeEventType.HARNESS: 0.0,
}

_RISK_EVENT_TYPES = {
    RuntimeEventType.NETWORK,
    RuntimeEventType.DNS,
    RuntimeEventType.PERSISTENCE,
    RuntimeEventType.CREDENTIAL,
    RuntimeEventType.DEFENSE_EVASION,
}

_RUNTIME_PATHS = (
    ("credential-access", "network"),
    ("evasion", "execution"),
    ("execution", "persistence"),
)


def _related(left: RuntimeEvent, right: RuntimeEvent) -> bool:
    ids_left = {left.process_id, left.parent_process_id} - {None}
    ids_right = {right.process_id, right.parent_process_id} - {None}
    return bool(ids_left & ids_right) and datetime.fromisoformat(
        left.timestamp.replace("Z", "+00:00")
    ) <= datetime.fromisoformat(right.timestamp.replace("Z", "+00:00"))


def analyze_runtime_trace(
    trace: RuntimeTrace,
) -> tuple[list[EvidenceItem], list[AttackPath]]:
    confidence = 0.98 if trace.trusted else 0.35
    evidence: list[EvidenceItem] = []
    by_stage: dict[str, list[tuple[RuntimeEvent, EvidenceItem]]] = defaultdict(list)
    for index, event in enumerate(trace.events):
        stage = _TYPE_STAGE.get(event.event_type)
        if stage is None:
            continue
        evidence_id = f"runtime:{trace.run_id}:{index}"
        target = event.target or event.destination or event.command or event.action
        item = EvidenceItem(
            evidence_id=evidence_id,
            source=EvidenceSource.RUNTIME,
            kind=stage,
            polarity=(
                EvidencePolarity.RISK
                if event.event_type in _RISK_EVENT_TYPES
                else EvidencePolarity.CONTEXT
            ),
            strength=(
                _EVENT_STRENGTH[event.event_type]
                * (0.6 if event.success is False else 1.0)
            ),
            confidence=confidence,
            summary=f"Runtime {stage} observation: {event.action}",
            details={
                "target": target,
                "process": event.process,
                "process_id": event.process_id,
                "trace_sha256": trace.trace_sha256,
                "trace_trusted": trace.trusted,
                "attack_techniques": list(techniques_for_runtime_stage(stage)),
            },
        )
        evidence.append(item)
        by_stage[stage].append((event, item))

    paths: list[AttackPath] = []
    for source, sink in _RUNTIME_PATHS:
        matches = [
            (left, right)
            for left in by_stage.get(source, [])
            for right in by_stage.get(sink, [])
            if _related(left[0], right[0])
            and (right[0].success is not False or sink == "network")
        ]
        if not matches:
            continue
        left, right = matches[0]
        paths.append(
            AttackPath(
                stages=(source, sink),
                confidence=confidence,
                evidence_ids=(left[1].evidence_id, right[1].evidence_id),
                runtime_confirmed=trace.trusted,
            )
        )
    return evidence, paths
