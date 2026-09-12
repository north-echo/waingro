"""Correlate independent evidence without equating dangerousness with intent."""

from __future__ import annotations

from urllib.parse import urlsplit

from waingro.analyzers.behavior_graph import build_static_attack_paths
from waingro.analyzers.runtime import analyze_runtime_trace
from waingro.dynamic.models import RuntimeEventType, RuntimeTrace
from waingro.ecosystem import EcosystemContext
from waingro.evidence import (
    AssessmentVerdict,
    EvidenceDimension,
    EvidenceItem,
    EvidencePolarity,
    EvidenceSource,
    HybridAssessment,
)
from waingro.models import ScanResult, Severity
from waingro.resolvers.dependency_graph import DependencyGraph
from waingro.resolvers.osv import PackageVulnerabilityResult
from waingro.resolvers.package_artifact import PackageArtifactInspection
from waingro.resolvers.package_registry import PackageResolution
from waingro.ttps import techniques_for_finding

_SEVERITY_STRENGTH = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.45,
    Severity.LOW: 0.2,
    Severity.INFO: 0.05,
}


def _noisy_or(values: list[float]) -> float:
    remaining = 1.0
    for value in values:
        remaining *= 1.0 - max(0.0, min(value, 1.0))
    return 1.0 - remaining


def _dimension(items: list[EvidenceItem], *, trust: bool = False) -> EvidenceDimension:
    selected = [
        item
        for item in items
        if item.polarity == (EvidencePolarity.TRUST if trust else EvidencePolarity.RISK)
    ]
    weighted = [item.strength * item.confidence for item in selected]
    score = _noisy_or(weighted)
    confidence = max((item.confidence for item in selected), default=0.0)
    return EvidenceDimension(
        score=round(score, 3),
        confidence=round(confidence, 3),
        evidence_ids=tuple(item.evidence_id for item in selected),
    )


def _static_evidence(result: ScanResult) -> tuple[list[EvidenceItem], dict[int, EvidenceItem]]:
    items = []
    mapping = {}
    root = result.skill_path if result.skill_path.is_dir() else result.skill_path.parent
    for index, finding in enumerate(result.findings):
        path = finding.file_path
        manifest_only = path.name == "SKILL.md"
        try:
            relative = str(path.relative_to(root))
        except ValueError:
            relative = str(path)
        # SKILL.md instructions may be followed by an agent, so they are not
        # inert documentation. They remain less directly reachable than a
        # bundled executable file.
        reachability = 0.45 if manifest_only else 0.8
        if finding.rule_id.startswith("BEHAV-"):
            reachability = max(reachability, 0.85)
        item = EvidenceItem(
            evidence_id=f"static:{finding.rule_id}:{index}",
            source=EvidenceSource.STATIC,
            kind=finding.category.value,
            polarity=EvidencePolarity.RISK,
            strength=_SEVERITY_STRENGTH[finding.severity] * reachability,
            confidence=finding.confidence,
            summary=f"{finding.rule_id}: {finding.title}",
            details={
                "file": relative,
                "line": finding.line_number,
                "severity": finding.severity.value,
                "reachability": reachability,
                "attack_techniques": list(techniques_for_finding(finding)),
            },
        )
        items.append(item)
        mapping[id(finding)] = item
    return items, mapping


def _same_repository(left: str | None, right: str | None) -> bool | None:
    if not left or not right:
        return None
    def normalized(value: str) -> str:
        value = value.removeprefix("git+").removesuffix(".git").rstrip("/")
        parsed = urlsplit(value)
        return f"{parsed.hostname or ''}{parsed.path}".lower()
    return normalized(left) == normalized(right)


def _package_evidence(
    resolutions: list[PackageResolution],
    inspections: list[PackageArtifactInspection],
) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    for index, resolution in enumerate(resolutions):
        prefix = f"registry:{resolution.ecosystem}:{resolution.name or index}"
        if resolution.mutable and resolution.status == "resolved":
            items.append(EvidenceItem(
                evidence_id=f"{prefix}:mutable",
                source=EvidenceSource.REGISTRY,
                kind="mutable-resolution",
                polarity=EvidencePolarity.RISK,
                strength=0.35,
                confidence=0.95,
                summary="Package runner selector is mutable",
                details={
                    "requested": resolution.requested,
                    "resolved": resolution.resolved_version,
                },
            ))
        if resolution.version_age_days is not None and resolution.version_age_days < 7:
            items.append(EvidenceItem(
                evidence_id=f"{prefix}:new-version",
                source=EvidenceSource.REPUTATION,
                kind="new-version",
                polarity=EvidencePolarity.RISK,
                strength=0.25,
                confidence=0.9,
                summary="Resolved package version is less than seven days old",
                details={"age_days": resolution.version_age_days},
            ))
        if resolution.package_age_days is not None and resolution.package_age_days < 30:
            items.append(EvidenceItem(
                evidence_id=f"{prefix}:new-package",
                source=EvidenceSource.REPUTATION,
                kind="new-package",
                polarity=EvidencePolarity.RISK,
                strength=0.5,
                confidence=0.9,
                summary="Package identity is less than thirty days old",
                details={"age_days": resolution.package_age_days},
            ))
        if resolution.version_count is not None and resolution.version_count <= 2:
            items.append(EvidenceItem(
                evidence_id=f"{prefix}:few-versions",
                source=EvidenceSource.REPUTATION,
                kind="limited-history",
                polarity=EvidencePolarity.RISK,
                strength=0.25,
                confidence=0.75,
                summary="Package has very limited registry history",
                details={"version_count": resolution.version_count},
            ))
        if resolution.maintainer_count == 1:
            items.append(EvidenceItem(
                evidence_id=f"{prefix}:single-maintainer",
                source=EvidenceSource.REPUTATION,
                kind="single-maintainer",
                polarity=EvidencePolarity.CONTEXT,
                strength=0.15,
                confidence=0.8,
                summary="Registry metadata lists one maintainer",
            ))
        if resolution.provenance_subject_matches is False:
            items.append(EvidenceItem(
                evidence_id=f"{prefix}:provenance-mismatch",
                source=EvidenceSource.PROVENANCE,
                kind="subject-mismatch",
                polarity=EvidencePolarity.RISK,
                strength=0.9,
                confidence=0.95,
                summary="Provenance subject does not match registry integrity",
            ))
        elif resolution.cryptographic_verification == "verified":
            items.append(EvidenceItem(
                evidence_id=f"{prefix}:provenance-verified",
                source=EvidenceSource.PROVENANCE,
                kind="verified-provenance",
                polarity=EvidencePolarity.TRUST,
                strength=0.95,
                confidence=0.98,
                summary="Package provenance and transparency evidence were verified",
            ))
        elif resolution.provenance_subject_matches:
            items.append(EvidenceItem(
                evidence_id=f"{prefix}:provenance-claim",
                source=EvidenceSource.PROVENANCE,
                kind="unverified-provenance-claim",
                polarity=EvidencePolarity.CONTEXT,
                strength=0.35,
                confidence=0.5,
                summary="Provenance payload matches integrity but its signature is unverified",
            ))
        repositories_match = _same_repository(
            resolution.repository_url, resolution.build_source_repository
        )
        if repositories_match is False:
            items.append(EvidenceItem(
                evidence_id=f"{prefix}:repository-mismatch",
                source=EvidenceSource.PROVENANCE,
                kind="repository-mismatch",
                polarity=EvidencePolarity.RISK,
                strength=0.65,
                confidence=0.8,
                summary="Registry repository and provenance repository disagree",
            ))

    for index, inspection in enumerate(inspections):
        prefix = f"artifact:{inspection.ecosystem}:{inspection.name or index}"
        if inspection.status in {"integrity-mismatch", "identity-mismatch", "unsafe-archive"}:
            items.append(EvidenceItem(
                evidence_id=f"{prefix}:{inspection.status}",
                source=EvidenceSource.ARTIFACT,
                kind=inspection.status,
                polarity=EvidencePolarity.RISK,
                strength=0.95,
                confidence=0.98,
                summary=inspection.reason or f"Package artifact status is {inspection.status}",
            ))
        elif inspection.status == "inspected" and inspection.integrity_verified:
            items.append(EvidenceItem(
                evidence_id=f"{prefix}:integrity",
                source=EvidenceSource.ARTIFACT,
                kind="verified-integrity",
                polarity=EvidencePolarity.TRUST,
                strength=0.8,
                confidence=0.98,
                summary="Downloaded package artifact matched registry integrity and identity",
            ))
        if inspection.install_time_scripts:
            items.append(EvidenceItem(
                evidence_id=f"{prefix}:install-scripts",
                source=EvidenceSource.ARTIFACT,
                kind="install-time-code",
                polarity=EvidencePolarity.RISK,
                strength=0.65,
                confidence=0.95,
                summary="Package declares install-time lifecycle code",
                details={"scripts": sorted(inspection.install_time_scripts)},
            ))
    return items


def _ecosystem_evidence(context: EcosystemContext | None) -> list[EvidenceItem]:
    if context is None:
        return []
    items = []
    if context.exact_artifact_malicious:
        items.append(EvidenceItem(
            evidence_id="intel:exact-artifact",
            source=EvidenceSource.EXTERNAL_INTELLIGENCE,
            kind="confirmed-malicious-artifact",
            polarity=EvidencePolarity.RISK,
            strength=1.0,
            confidence=0.99,
            summary="An external source identifies this exact artifact digest as malicious",
            details={"source": context.intelligence_source},
        ))
    if context.publisher_age_days is not None and context.publisher_age_days < 14:
        items.append(EvidenceItem(
            evidence_id="reputation:new-publisher",
            source=EvidenceSource.REPUTATION,
            kind="new-publisher",
            polarity=EvidencePolarity.RISK,
            strength=0.4,
            confidence=0.8,
            summary="Publisher identity is less than fourteen days old",
            details={"age_days": context.publisher_age_days},
        ))
    if context.publisher_skill_count == 1:
        items.append(EvidenceItem(
            evidence_id="reputation:first-skill",
            source=EvidenceSource.REPUTATION,
            kind="limited-publisher-history",
            polarity=EvidencePolarity.CONTEXT,
            strength=0.2,
            confidence=0.8,
            summary="This is the publisher's only observed skill",
        ))
    if context.source_matches_registry is False:
        items.append(EvidenceItem(
            evidence_id="provenance:source-mismatch",
            source=EvidenceSource.PROVENANCE,
            kind="source-mismatch",
            polarity=EvidencePolarity.RISK,
            strength=0.8,
            confidence=0.9,
            summary="Registry content does not match the declared source",
        ))
    if context.publisher_verified:
        items.append(EvidenceItem(
            evidence_id="reputation:verified-publisher",
            source=EvidenceSource.REPUTATION,
            kind="verified-publisher",
            polarity=EvidencePolarity.TRUST,
            strength=0.5,
            confidence=0.9,
            summary="Registry marks the publisher identity as verified",
        ))
    return items


def _vulnerability_evidence(
    results: list[PackageVulnerabilityResult],
) -> list[EvidenceItem]:
    items = []
    for result in results:
        for record in result.vulnerabilities:
            malicious = record.malicious_package_advisory
            items.append(EvidenceItem(
                evidence_id=(
                    f"osv:{result.ecosystem}:{result.name}@{result.version}:"
                    f"{record.vulnerability_id}"
                ),
                source=EvidenceSource.EXTERNAL_INTELLIGENCE,
                kind=("malicious-package-version" if malicious else "known-vulnerability"),
                polarity=EvidencePolarity.RISK,
                strength=0.95 if malicious else 0.35,
                confidence=0.95,
                summary=(
                    "OSV identifies the resolved package version in a malicious-package advisory"
                    if malicious
                    else "OSV reports a vulnerability for the resolved package version"
                ),
                details={
                    "id": record.vulnerability_id,
                    "package": result.name,
                    "version": result.version,
                    "modified": record.modified,
                },
            ))
    return items


def assess_scan(
    result: ScanResult,
    *,
    resolutions: list[PackageResolution] | None = None,
    inspections: list[PackageArtifactInspection] | None = None,
    vulnerabilities: list[PackageVulnerabilityResult] | None = None,
    ecosystem_context: EcosystemContext | None = None,
    runtime_trace: RuntimeTrace | None = None,
    dependency_graph: DependencyGraph | None = None,
) -> HybridAssessment:
    """Create an explainable hybrid assessment from independently scoped evidence."""
    resolutions = resolutions or []
    inspections = inspections or []
    vulnerabilities = vulnerabilities or []
    static_items, mapping = _static_evidence(result)
    static_paths = build_static_attack_paths(result.findings, mapping)
    package_items = _package_evidence(resolutions, inspections)
    ecosystem_items = _ecosystem_evidence(ecosystem_context)
    vulnerability_items = _vulnerability_evidence(vulnerabilities)
    runtime_items = []
    runtime_paths = []
    if runtime_trace is not None:
        runtime_items, runtime_paths = analyze_runtime_trace(runtime_trace)
    evidence = [
        *static_items,
        *package_items,
        *ecosystem_items,
        *vulnerability_items,
        *runtime_items,
    ]
    paths = [*static_paths, *runtime_paths]

    capability = _dimension(static_items + [
        item for item in package_items if item.kind == "install-time-code"
    ])
    reachability_values = [
        float(item.details.get("reachability", 0.0)) * item.confidence
        for item in static_items
    ]
    reachability = EvidenceDimension(
        score=round(max(reachability_values, default=0.0), 3),
        confidence=round(max((item.confidence for item in static_items), default=0.0), 3),
        evidence_ids=tuple(item.evidence_id for item in static_items),
    )
    provenance_items = [item for item in evidence if item.source == EvidenceSource.PROVENANCE]
    provenance = _dimension(provenance_items, trust=True)
    reputation_items = [item for item in evidence if item.source == EvidenceSource.REPUTATION]
    reputation = _dimension(reputation_items)
    behavior_score = max((path.confidence for path in paths), default=0.0)
    behavior = EvidenceDimension(
        score=round(behavior_score, 3),
        confidence=round(behavior_score, 3),
        evidence_ids=tuple(dict.fromkeys(eid for path in paths for eid in path.evidence_ids)),
    )

    trusted_runtime_path = any(path.runtime_confirmed for path in runtime_paths)
    credential_targets_by_pid: dict[int, set[str]] = {}
    network_pids: set[int] = set()
    if runtime_trace is not None and runtime_trace.trusted:
        for event in runtime_trace.events:
            if event.process_id is None:
                continue
            if (
                event.event_type == RuntimeEventType.CREDENTIAL
                and event.success is not False
            ):
                credential_targets_by_pid.setdefault(event.process_id, set()).add(
                    event.target or "<unknown>"
                )
            elif event.event_type == RuntimeEventType.NETWORK:
                network_pids.add(event.process_id)
    trusted_multi_source_exfil = any(
        process_id in network_pids and len(targets) >= 2
        for process_id, targets in credential_targets_by_pid.items()
    )
    exact_intel = any(item.kind == "confirmed-malicious-artifact" for item in evidence)
    malicious_package = any(item.kind == "malicious-package-version" for item in evidence)
    severe_artifact_anomaly = any(
        item.source == EvidenceSource.ARTIFACT
        and item.polarity == EvidencePolarity.RISK
        and item.strength >= 0.9
        for item in evidence
    )
    provenance_anomaly = any(
        item.source == EvidenceSource.PROVENANCE
        and item.polarity == EvidencePolarity.RISK
        for item in evidence
    )
    direct_exfil = any(finding.rule_id == "NET-004" for finding in result.findings)

    if exact_intel:
        maliciousness = 0.99
    elif trusted_multi_source_exfil:
        maliciousness = 0.95
    elif trusted_runtime_path:
        # One process reading one credential source and attempting a connection
        # is also compatible with legitimate deployment tools. Require
        # multi-source harvesting before assigning MALICIOUS.
        maliciousness = 0.82
    elif malicious_package and capability.score >= 0.4:
        # OSV binds package identity and version, not the complete skill
        # artifact, so it warrants suspicion but not an automatic conviction.
        maliciousness = 0.82
    elif severe_artifact_anomaly and capability.score >= 0.4:
        maliciousness = 0.78
    elif provenance_anomaly and capability.score >= 0.4:
        maliciousness = 0.7
    elif static_paths or direct_exfil:
        maliciousness = min(
            0.69,
            0.42 + 0.2 * behavior.score + 0.12 * reachability.score
            + 0.08 * reputation.score,
        )
    elif capability.score > 0:
        maliciousness = min(0.44, 0.12 + 0.24 * capability.score + 0.08 * reputation.score)
    elif severe_artifact_anomaly:
        maliciousness = 0.55
    else:
        maliciousness = 0.0
    maliciousness_dimension = EvidenceDimension(
        score=round(maliciousness, 3),
        confidence=round(max((item.confidence for item in evidence), default=0.0), 3),
        evidence_ids=tuple(
            item.evidence_id
            for item in evidence
            if item.polarity == EvidencePolarity.RISK
        ),
    )

    missing = []
    if not resolutions and result.package_references:
        missing.append("package-resolution")
    if not inspections and any(
        reference.network_allowed for reference in result.package_references
    ):
        missing.append("package-artifact-inspection")
    if ecosystem_context is None:
        missing.append("ecosystem-context")
    if resolutions and not vulnerabilities:
        missing.append("vulnerability-intelligence")
    if dependency_graph is not None and (
        dependency_graph.truncated or dependency_graph.unresolved_ranges
    ):
        missing.append("dependency-graph-completeness")
    if runtime_trace is None:
        missing.append("runtime-trace")
    elif not runtime_trace.trusted:
        missing.append("authenticated-runtime-trace")

    if maliciousness >= 0.85 and (trusted_multi_source_exfil or exact_intel):
        verdict = AssessmentVerdict.MALICIOUS
    elif maliciousness >= 0.6:
        verdict = AssessmentVerdict.SUSPICIOUS
    elif result.security_tool_score >= 0.5 and not trusted_runtime_path:
        verdict = AssessmentVerdict.REVIEW
    elif capability.score > 0 or severe_artifact_anomaly:
        verdict = AssessmentVerdict.CAPABILITY
    elif any(item.polarity == EvidencePolarity.RISK for item in evidence):
        verdict = AssessmentVerdict.REVIEW
    else:
        verdict = AssessmentVerdict.CLEAN

    trusted_runtime_risk = bool(
        runtime_trace is not None
        and runtime_trace.trusted
        and any(
            item.source == EvidenceSource.RUNTIME
            and item.polarity == EvidencePolarity.RISK
            for item in runtime_items
        )
    )
    if runtime_trace is None:
        runtime_coverage = "not-run"
    elif not runtime_trace.trusted:
        runtime_coverage = "untrusted"
    elif trusted_runtime_path:
        runtime_coverage = "attack-path-observed"
    elif trusted_runtime_risk:
        runtime_coverage = "risk-behavior-observed"
    else:
        runtime_coverage = "no-relevant-behavior"

    # An isolated run is coverage, not a box-check. A trace that only proves
    # the interpreter started cannot retire a static attack path. High-priority
    # recommendations are reserved for correlated suspicious paths; isolated
    # dangerous primitives remain visible as medium-priority opportunities.
    path_covered = trusted_runtime_path if (static_paths or direct_exfil) else trusted_runtime_risk
    eligible_for_dynamic = (
        capability.score >= 0.4
        and result.security_tool_score < 0.5
        and not path_covered
    )
    if verdict == AssessmentVerdict.SUSPICIOUS and eligible_for_dynamic:
        dynamic_priority = "high"
    elif verdict == AssessmentVerdict.CAPABILITY and eligible_for_dynamic:
        dynamic_priority = "medium"
    else:
        dynamic_priority = "none"
    dynamic_recommended = dynamic_priority == "high"
    if (
        dynamic_priority != "none"
        and runtime_trace is not None
        and runtime_trace.trusted
    ):
        missing.append("runtime-behavior-coverage")
    rationale = [
        f"Static capability score is {capability.score:.3f}; "
        "this measures dangerousness, not intent.",
        f"Correlated maliciousness confidence is {maliciousness:.3f}.",
    ]
    if static_paths:
        rationale.append(f"Found {len(static_paths)} same-file static attack path(s).")
    if runtime_trace is not None:
        rationale.append(
            "Runtime evidence is authenticated and policy-conformant."
            if runtime_trace.trusted
            else "Runtime evidence is untrusted and cannot independently establish intent."
        )
        rationale.append(f"Runtime coverage is {runtime_coverage}.")
    if missing:
        rationale.append("Missing evidence: " + ", ".join(missing) + ".")

    return HybridAssessment(
        verdict=verdict,
        dimensions={
            "behavioral_evidence": behavior,
            "capability_severity": capability,
            "maliciousness_confidence": maliciousness_dimension,
            "provenance_confidence": provenance,
            "reachability": reachability,
            "reputation_risk": reputation,
        },
        evidence=tuple(evidence),
        attack_paths=tuple(paths),
        missing_evidence=tuple(missing),
        rationale=tuple(rationale),
        dynamic_recommended=dynamic_recommended,
        dynamic_priority=dynamic_priority,
        runtime_coverage=runtime_coverage,
    )
