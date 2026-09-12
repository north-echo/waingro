"""Tests for hybrid evidence correlation and verdict separation."""

from pathlib import Path

from waingro.analyzers.hybrid import assess_scan
from waingro.dynamic.models import (
    IsolationRecord,
    RuntimeCoverage,
    RuntimeEvent,
    RuntimeEventType,
    RuntimeTrace,
)
from waingro.ecosystem import EcosystemContext
from waingro.evidence import AssessmentVerdict
from waingro.resolvers.osv import PackageVulnerabilityResult, VulnerabilityRecord
from waingro.resolvers.package_artifact import PackageArtifactInspection
from waingro.resolvers.package_registry import PackageResolution
from waingro.scanner import scan_skill

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _trace(*, trusted: bool, credential_targets: int = 2) -> RuntimeTrace:
    isolation = IsolationRecord(
        hypervisor="libvirt-kvm",
        hardware_virtualization=True,
        ephemeral_disk=True,
        host_shares=False,
        host_credentials=False,
        network_policy="none",
        base_image_sha256="b" * 64,
        candidate_read_only=True,
    )
    credentials = (
        RuntimeEvent(
            RuntimeEventType.CREDENTIAL,
            "read",
            f"2026-09-11T12:00:0{index + 1}Z",
            process_id=42,
            target=target,
        )
        for index, target in enumerate(
            (
                "/home/analyst/.aws/credentials",
                "/home/analyst/.config/waingro-canary-token",
            )[:credential_targets]
        )
    )
    events = (*credentials,
        RuntimeEvent(
            RuntimeEventType.NETWORK,
            "connect",
            "2026-09-11T12:00:05Z",
            process_id=42,
            destination="192.0.2.1:443",
        ),
    )
    return RuntimeTrace(
        run_id="test-run",
        artifact_sha256="a" * 64,
        host="hanna2",
        backend="libvirt-kvm",
        started_at="2026-09-11T12:00:00Z",
        finished_at="2026-09-11T12:01:00Z",
        exit_status="completed",
        isolation=isolation,
        events=events,
        trace_sha256="c" * 64,
        signature_verified=trusted,
        signature_identity="hanna2" if trusted else None,
        base_image_verified=trusted,
    )


def test_clean_static_assessment_is_clean():
    result = scan_skill(FIXTURES / "clean" / "basic-skill")

    assessment = assess_scan(result)

    assert assessment.verdict == AssessmentVerdict.CLEAN
    assert assessment.dimensions["capability_severity"].score == 0
    assert "runtime-trace" in assessment.missing_evidence


def test_single_dangerous_primitive_is_capability_not_intent():
    result = scan_skill(FIXTURES / "malicious" / "clawhavoc-curl-pipe")

    assessment = assess_scan(result)

    assert assessment.verdict == AssessmentVerdict.CAPABILITY
    assert assessment.dynamic_recommended is False
    assert assessment.dynamic_priority == "medium"
    assert assessment.dimensions["maliciousness_confidence"].score < 0.6


def test_same_file_static_attack_chain_can_be_suspicious_but_not_malicious():
    result = scan_skill(FIXTURES / "malicious" / "clawhavoc-base64")

    assessment = assess_scan(result)

    assert assessment.verdict == AssessmentVerdict.SUSPICIOUS
    assert assessment.attack_paths
    assert assessment.dynamic_recommended is True
    assert assessment.dynamic_priority == "high"
    assert assessment.dimensions["maliciousness_confidence"].score < 0.85


def test_probable_security_tool_is_review_not_dynamic_execution_target():
    result = scan_skill(FIXTURES / "malicious" / "clawhavoc-base64")
    result.security_tool_score = 0.4

    assessment = assess_scan(result)

    assert assessment.verdict == AssessmentVerdict.REVIEW
    assert assessment.dynamic_priority == "none"


def test_empty_authenticated_trace_does_not_retire_static_attack_path():
    result = scan_skill(FIXTURES / "malicious" / "clawhavoc-base64")
    trace = _trace(trusted=True, credential_targets=0)
    trace = RuntimeTrace(
        **{
            **trace.__dict__,
            "events": (
                RuntimeEvent(
                    RuntimeEventType.PROCESS,
                    "exec",
                    "2026-09-11T12:00:01Z",
                    process_id=42,
                    process="/usr/bin/bash",
                ),
            ),
        }
    )

    assessment = assess_scan(result, runtime_trace=trace)

    assert assessment.dynamic_recommended is True
    assert assessment.dynamic_priority == "high"
    assert assessment.runtime_coverage == "no-relevant-behavior"
    assert "runtime-behavior-coverage" in assessment.missing_evidence


def test_incomplete_explicit_scenario_does_not_retire_static_attack_path():
    result = scan_skill(FIXTURES / "malicious" / "clawhavoc-base64")
    trace = _trace(trusted=True, credential_targets=0)
    trace = RuntimeTrace(
        **{
            **trace.__dict__,
            "coverage": RuntimeCoverage(
                required_event_types=(RuntimeEventType.CREDENTIAL, RuntimeEventType.NETWORK),
                observed_event_types=(RuntimeEventType.NETWORK,),
                missing_event_types=(RuntimeEventType.CREDENTIAL,),
                require_exit_zero=True,
                exit_status_satisfied=False,
                complete=False,
            ),
        }
    )

    assessment = assess_scan(result, runtime_trace=trace)

    assert assessment.runtime_coverage == "scenario-incomplete"
    assert assessment.dynamic_priority == "high"
    assert "runtime-scenario-coverage" in assessment.missing_evidence


def test_authenticated_runtime_exfiltration_chain_can_establish_maliciousness():
    result = scan_skill(FIXTURES / "clean" / "basic-skill")

    assessment = assess_scan(result, runtime_trace=_trace(trusted=True))

    assert assessment.verdict == AssessmentVerdict.MALICIOUS
    assert any(path.runtime_confirmed for path in assessment.attack_paths)
    assert assessment.runtime_coverage == "attack-path-observed"
    assert assessment.dynamic_priority == "none"


def test_unauthenticated_runtime_trace_cannot_establish_maliciousness():
    result = scan_skill(FIXTURES / "clean" / "basic-skill")

    assessment = assess_scan(result, runtime_trace=_trace(trusted=False))

    assert assessment.verdict == AssessmentVerdict.REVIEW
    assert "authenticated-runtime-trace" in assessment.missing_evidence


def test_single_source_runtime_connection_is_suspicious_not_malicious():
    result = scan_skill(FIXTURES / "clean" / "basic-skill")

    assessment = assess_scan(
        result,
        runtime_trace=_trace(trusted=True, credential_targets=1),
    )

    assert assessment.verdict == AssessmentVerdict.SUSPICIOUS


def test_normal_runtime_process_and_file_events_remain_context():
    result = scan_skill(FIXTURES / "clean" / "basic-skill")
    trace = _trace(trusted=True, credential_targets=0)
    trace = RuntimeTrace(
        **{
            **trace.__dict__,
            "events": (
                RuntimeEvent(
                    RuntimeEventType.PROCESS,
                    "exec",
                    "2026-09-11T12:00:01Z",
                    process_id=42,
                    process="/usr/bin/python3",
                ),
                RuntimeEvent(
                    RuntimeEventType.FILE,
                    "write",
                    "2026-09-11T12:00:02Z",
                    process_id=42,
                    target="/tmp/benign.txt",
                ),
            ),
        }
    )

    assessment = assess_scan(result, runtime_trace=trace)

    assert assessment.verdict == AssessmentVerdict.CLEAN


def test_unresolved_dependency_range_is_missing_context_not_risk():
    result = scan_skill(FIXTURES / "clean" / "basic-skill")
    resolution = PackageResolution(
        ecosystem="npm",
        name="dependency",
        requested="^1.0.0",
        status="unresolved",
        mutable=True,
    )

    assessment = assess_scan(result, resolutions=[resolution])

    assert assessment.verdict == AssessmentVerdict.CLEAN
    assert not any(item.kind == "mutable-resolution" for item in assessment.evidence)


def test_package_identity_anomaly_correlates_with_execution_capability():
    result = scan_skill(FIXTURES / "malicious" / "clawhavoc-curl-pipe")
    resolution = PackageResolution(
        ecosystem="npm",
        name="example",
        requested="latest",
        status="resolved",
        mutable=True,
        resolved_version="1.0.0",
    )
    inspection = PackageArtifactInspection(
        ecosystem="npm",
        name="example",
        version="1.0.0",
        status="identity-mismatch",
        artifact_url="https://registry.npmjs.org/example/-/example-1.0.0.tgz",
        reason="package name mismatch",
    )

    assessment = assess_scan(
        result,
        resolutions=[resolution],
        inspections=[inspection],
    )

    assert assessment.verdict == AssessmentVerdict.SUSPICIOUS


def test_exact_digest_intelligence_is_required_for_external_malicious_label():
    result = scan_skill(FIXTURES / "clean" / "basic-skill")
    context = EcosystemContext(
        artifact_sha256=result.artifact_identity.sha256,
        exact_artifact_malicious=True,
        intelligence_source="https://example.invalid/advisory/1",
    )

    assessment = assess_scan(result, ecosystem_context=context)

    assert assessment.verdict == AssessmentVerdict.MALICIOUS


def test_osv_malicious_package_version_requires_correlated_capability():
    result = scan_skill(FIXTURES / "malicious" / "clawhavoc-curl-pipe")
    intelligence = PackageVulnerabilityResult(
        ecosystem="npm",
        name="example",
        version="1.0.0",
        status="matched",
        vulnerabilities=(VulnerabilityRecord("MAL-2026-1234"),),
    )

    assessment = assess_scan(result, vulnerabilities=[intelligence])

    assert assessment.verdict == AssessmentVerdict.SUSPICIOUS
    assert assessment.verdict != AssessmentVerdict.MALICIOUS
