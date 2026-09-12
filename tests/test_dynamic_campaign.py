"""Tests for non-executing dynamic campaign preparation."""

import json

from waingro.dynamic.campaign import prepare_campaign_queue


def _record(path, digest, *, confidence=0.95, rule="EXFIL-008", tool_score=0.1):
    return {
        "path": str(path),
        "publisher": path.parent.name,
        "slug": path.name,
        "artifact_sha256": digest,
        "static_verdict": "SUSPICIOUS",
        "hybrid_verdict": "SUSPICIOUS",
        "dynamic_priority": "high",
        "security_tool_score": tool_score,
        "attack_paths": [{"confidence": confidence, "stages": ["data-access", "exfiltration"]}],
        "findings": [{"rule": rule, "severity": "high"}],
    }


def _candidate(root, publisher, slug, *, runnable=True):
    candidate = root / publisher / slug
    candidate.mkdir(parents=True)
    (candidate / "SKILL.md").write_text("# fixture\n", encoding="utf-8")
    if runnable:
        scripts = candidate / "scripts"
        scripts.mkdir()
        (scripts / "run.py").write_text("print('fixture')\n", encoding="utf-8")
    return candidate


def test_campaign_queue_is_bounded_deduplicated_and_never_authorized(tmp_path):
    corpus = tmp_path / "corpus"
    selected = _candidate(corpus, "publisher", "selected")
    secret = _candidate(corpus, "publisher", "secret")
    tool = _candidate(corpus, "publisher", "tool")
    annotated_tool = _candidate(corpus, "publisher", "annotated-tool")
    no_entrypoint = _candidate(corpus, "publisher", "docs-only", runnable=False)
    records = [
        _record(selected, "a" * 64),
        _record(selected, "a" * 64),
        _record(secret, "b" * 64, rule="EXFIL-006"),
        _record(tool, "c" * 64, tool_score=0.8),
        {
            **_record(annotated_tool, "e" * 64),
            "findings": [{
                "rule": "NET-002",
                "severity": "critical",
                "note": "Skill name matches security tool pattern.",
            }],
        },
        _record(no_entrypoint, "d" * 64),
    ]
    source = tmp_path / "scan.jsonl"
    source.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
    output = tmp_path / "queue.json"

    report = prepare_campaign_queue(source, corpus, output, limit=10)

    assert report["execution_authorized"] is False
    assert report["counts"]["selected_for_manual_review"] == 1
    assert report["counts"]["excluded"] == {
        "duplicate-artifact": 1,
        "no-explicit-runnable-entrypoint": 1,
        "possible-embedded-credential": 1,
        "probable-security-tool": 2,
    }
    candidate = report["candidates"][0]
    assert candidate["artifact_sha256"] == "a" * 64
    assert candidate["execution_authorized"] is False
    assert candidate["review_status"] == "manual-review-required"
    assert candidate["entrypoint_candidates"] == [
        {"path": "scripts/run.py", "interpreter": "python"}
    ]
    assert json.loads(output.read_text(encoding="utf-8")) == report


def test_campaign_queue_requires_path_beneath_exact_two_level_corpus(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    outside = _candidate(tmp_path / "outside", "publisher", "candidate")
    source = tmp_path / "scan.jsonl"
    source.write_text(json.dumps(_record(outside, "a" * 64)) + "\n", encoding="utf-8")
    output = tmp_path / "queue.json"

    report = prepare_campaign_queue(source, corpus, output)

    assert report["counts"]["selected_for_manual_review"] == 0
    assert report["counts"]["excluded"]["unsafe-or-missing-path"] == 1


def test_campaign_queue_rejects_a_symlinked_candidate(tmp_path):
    corpus = tmp_path / "corpus"
    real = _candidate(tmp_path / "source", "publisher", "candidate")
    publisher = corpus / "publisher"
    publisher.mkdir(parents=True)
    candidate = publisher / "candidate"
    candidate.symlink_to(real, target_is_directory=True)
    source = tmp_path / "scan.jsonl"
    source.write_text(json.dumps(_record(candidate, "a" * 64)) + "\n", encoding="utf-8")
    output = tmp_path / "queue.json"

    report = prepare_campaign_queue(source, corpus, output)

    assert report["counts"]["selected_for_manual_review"] == 0
    assert report["counts"]["excluded"]["unsafe-or-missing-path"] == 1
