"""Tests for artifact-bound, non-executing provenance preparation."""

import json

import pytest
from click.testing import CliRunner

from waingro.cli import main
from waingro.provenance_review import (
    ProvenancePreparationError,
    apply_external_reviews,
    prepare_provenance_ledger,
)
from waingro.scanner import scan_skill


def _candidate(root, publisher, slug, repository):
    candidate = root / publisher / slug
    candidate.mkdir(parents=True)
    (candidate / "SKILL.md").write_text(
        "---\n"
        f"name: {slug}\n"
        f"repository: {repository}\n"
        "---\n"
        "Run scripts/run.py. Documentation: https://example.com/guide.\n",
        encoding="utf-8",
    )
    (candidate / "_meta.json").write_text(
        json.dumps({"ownerId": publisher, "slug": slug, "version": "1.0.0", "publishedAt": 1}),
        encoding="utf-8",
    )
    scripts = candidate / "scripts"
    scripts.mkdir()
    (scripts / "run.py").write_text("print('fixture')\n", encoding="utf-8")
    return candidate


def _queue(path, candidates, *, authorized=False):
    records = []
    for candidate in candidates:
        artifact = scan_skill(candidate).artifact_identity
        assert artifact is not None
        records.append(
            {
                "publisher": candidate.parent.name,
                "slug": candidate.name,
                "path": str(candidate),
                "artifact_sha256": artifact.sha256,
                "execution_authorized": False,
            }
        )
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.1",
                "corpus_root": str(candidates[0].parents[1]),
                "execution_authorized": authorized,
                "candidates": records,
            }
        ),
        encoding="utf-8",
    )


def test_prepare_provenance_verifies_identity_and_extracts_claims(tmp_path):
    corpus = tmp_path / "corpus"
    candidate = _candidate(
        corpus,
        "publisher",
        "candidate",
        "https://github.com/example-owner/example-repo/tree/main/skill",
    )
    queue = tmp_path / "queue.json"
    output = tmp_path / "provenance.json"
    _queue(queue, [candidate])

    report = prepare_provenance_ledger(queue, output)

    assert report["execution_authorized"] is False
    assert report["network_access_performed"] is False
    assert report["counts"] == {
        "candidates": 1,
        "artifact_identities_verified": 1,
        "registry_identities_matching": 1,
        "with_strong_source_claims": 1,
        "without_strong_source_claims": 0,
        "with_package_runner_references": 0,
        "content_equivalence_groups": 0,
        "core_content_equivalence_groups": 0,
    }
    record = report["candidates"][0]
    assert record["registry_metadata"]["identity_matches_queue"] is True
    assert record["source_claims"][0]["repository"] == (
        "https://github.com/example-owner/example-repo"
    )
    assert record["source_claims"][0]["subpath"] == "skill"
    assert record["source_claims"][0]["kind"] == "repository"
    assert record["registry_metadata"]["artifact_identity_verified"] is True
    assert record["external_verification"]["status"] == "not-checked"
    assert record["execution_authorized"] is False
    assert json.loads(output.read_text(encoding="utf-8")) == report


def test_prepare_provenance_rejects_changed_artifact(tmp_path):
    corpus = tmp_path / "corpus"
    candidate = _candidate(corpus, "publisher", "candidate", "https://github.com/o/r")
    queue = tmp_path / "queue.json"
    _queue(queue, [candidate])
    (candidate / "scripts" / "run.py").write_text("print('changed')\n", encoding="utf-8")

    with pytest.raises(ProvenancePreparationError, match="artifact SHA-256 mismatch"):
        prepare_provenance_ledger(queue, tmp_path / "provenance.json")


def test_prepare_provenance_rejects_authorized_queue(tmp_path):
    corpus = tmp_path / "corpus"
    candidate = _candidate(corpus, "publisher", "candidate", "https://github.com/o/r")
    queue = tmp_path / "queue.json"
    _queue(queue, [candidate], authorized=True)

    with pytest.raises(ProvenancePreparationError, match="requires an unauthorized queue"):
        prepare_provenance_ledger(queue, tmp_path / "provenance.json")


def test_provenance_prepare_cli_writes_verified_ledger(tmp_path):
    corpus = tmp_path / "corpus"
    candidate = _candidate(corpus, "publisher", "candidate", "https://github.com/o/r")
    queue = tmp_path / "queue.json"
    output = tmp_path / "provenance.json"
    _queue(queue, [candidate])

    result = CliRunner().invoke(
        main,
        ["provenance", "prepare", str(queue), "--output", str(output)],
    )

    assert result.exit_code == 0
    assert json.loads(result.output)["artifact_identities_verified"] == 1
    assert json.loads(output.read_text(encoding="utf-8"))["execution_authorized"] is False


def test_prepare_provenance_flags_equivalent_content_without_merging_publishers(tmp_path):
    corpus = tmp_path / "corpus"
    first = _candidate(corpus, "publisher-one", "same", "https://github.com/o/r")
    second = _candidate(corpus, "publisher-two", "same", "https://github.com/o/r")
    queue = tmp_path / "queue.json"
    output = tmp_path / "provenance.json"
    _queue(queue, [first, second])

    report = prepare_provenance_ledger(queue, output)

    assert report["counts"]["content_equivalence_groups"] == 1
    assert report["counts"]["core_content_equivalence_groups"] == 1
    assert report["candidates"][0]["artifact_sha256"] != report["candidates"][1]["artifact_sha256"]
    assert report["candidates"][0]["content_equivalent_queue_entries"] == [
        {
            "publisher": "publisher-two",
            "slug": "same",
            "artifact_sha256": report["candidates"][1]["artifact_sha256"],
        }
    ]
    assert report["candidates"][0]["core_content_equivalent_queue_entries"] == [
        {
            "publisher": "publisher-two",
            "slug": "same",
            "artifact_sha256": report["candidates"][1]["artifact_sha256"],
        }
    ]


def test_prepare_provenance_ignores_template_ports(tmp_path):
    corpus = tmp_path / "corpus"
    candidate = _candidate(corpus, "publisher", "candidate", "https://github.com/o/r")
    with (candidate / "SKILL.md").open("a", encoding="utf-8") as handle:
        handle.write("Template only: https://service.example:$PORT/path\n")
    queue = tmp_path / "queue.json"
    output = tmp_path / "provenance.json"
    _queue(queue, [candidate])

    report = prepare_provenance_ledger(queue, output)

    assert [item["host"] for item in report["candidates"][0]["service_hosts"]] == [
        "example.com",
        "github.com",
    ]


def test_bundled_repository_catalog_is_not_candidate_provenance(tmp_path):
    corpus = tmp_path / "corpus"
    candidate = _candidate(corpus, "publisher", "candidate", "https://github.com/o/r")
    (candidate / "scripts" / "catalog.js").write_text(
        'const command = "git clone https://github.com/someone/unrelated";\n',
        encoding="utf-8",
    )
    queue = tmp_path / "queue.json"
    output = tmp_path / "provenance.json"
    _queue(queue, [candidate])

    report = prepare_provenance_ledger(queue, output)

    claims = report["candidates"][0]["source_claims"]
    assert [item["repository"] for item in claims] == ["https://github.com/o/r"]


def test_reference_to_dependency_repository_is_not_a_strong_source_claim(tmp_path):
    corpus = tmp_path / "corpus"
    candidate = _candidate(
        corpus,
        "publisher",
        "candidate",
        "https://github.com/YOUR_USERNAME/candidate",
    )
    with (candidate / "SKILL.md").open("a", encoding="utf-8") as handle:
        handle.write("- [Dependency](https://github.com/vendor/dependency) - Official repository\n")
    queue = tmp_path / "queue.json"
    output = tmp_path / "provenance.json"
    _queue(queue, [candidate])

    report = prepare_provenance_ledger(queue, output)

    record = report["candidates"][0]
    assert record["strong_source_claim_count"] == 0
    assert any(item["placeholder"] for item in record["source_claims"])
    dependency = next(
        item
        for item in record["source_claims"]
        if item["repository"] == "https://github.com/vendor/dependency"
    )
    assert dependency["kind"] == "reference"


def test_apply_external_reviews_is_artifact_bound_and_preserves_intent_state(tmp_path):
    corpus = tmp_path / "corpus"
    candidate = _candidate(corpus, "publisher", "candidate", "https://github.com/o/r")
    queue = tmp_path / "queue.json"
    ledger = tmp_path / "ledger.json"
    reviews = tmp_path / "reviews.json"
    output = tmp_path / "reviewed.json"
    _queue(queue, [candidate])
    prepared = prepare_provenance_ledger(queue, ledger)
    digest = prepared["candidates"][0]["artifact_sha256"]
    reviews.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "reviews": [
                    {
                        "artifact_sha256": digest,
                        "status": "source-corroborated",
                        "repository": "https://github.com/o/r",
                        "revision": "a" * 40,
                        "artifact_source_match": "core",
                        "match_counts": {"total": 3, "matched": 2, "missing": 0, "changed": 1},
                        "evidence_urls": ["https://github.com/o/r/commit/" + "a" * 40],
                        "note": "One registry metadata file differs.",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    reviewed = apply_external_reviews(ledger, reviews, output)

    assert reviewed["external_reviews"]["intent_verdicts_changed"] is False
    assert reviewed["external_reviews"]["counts"] == {"source-corroborated": 1}
    assert reviewed["candidates"][0]["external_verification"]["revision"] == "a" * 40


def test_apply_external_reviews_rejects_unknown_artifact(tmp_path):
    corpus = tmp_path / "corpus"
    candidate = _candidate(corpus, "publisher", "candidate", "https://github.com/o/r")
    queue = tmp_path / "queue.json"
    ledger = tmp_path / "ledger.json"
    reviews = tmp_path / "reviews.json"
    _queue(queue, [candidate])
    prepare_provenance_ledger(queue, ledger)
    reviews.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "reviews": [
                    {
                        "artifact_sha256": "f" * 64,
                        "status": "source-unavailable",
                        "repository": None,
                        "revision": None,
                        "artifact_source_match": "unknown",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ProvenancePreparationError, match="not bound to a ledger artifact"):
        apply_external_reviews(ledger, reviews, tmp_path / "reviewed.json")


def test_apply_external_reviews_rejects_inconsistent_status(tmp_path):
    corpus = tmp_path / "corpus"
    candidate = _candidate(corpus, "publisher", "candidate", "https://github.com/o/r")
    queue = tmp_path / "queue.json"
    ledger = tmp_path / "ledger.json"
    reviews = tmp_path / "reviews.json"
    _queue(queue, [candidate])
    prepared = prepare_provenance_ledger(queue, ledger)
    reviews.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "reviews": [
                    {
                        "artifact_sha256": prepared["candidates"][0]["artifact_sha256"],
                        "status": "source-partially-corroborated",
                        "repository": "https://github.com/o/r",
                        "revision": "a" * 40,
                        "artifact_source_match": "full",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ProvenancePreparationError, match="requires a partial source match"):
        apply_external_reviews(ledger, reviews, tmp_path / "reviewed.json")
