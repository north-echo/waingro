"""Tests for exact-artifact ecosystem context."""

import json

import pytest

from waingro.ecosystem import load_ecosystem_context


def test_context_is_bound_to_exact_artifact(tmp_path):
    path = tmp_path / "context.json"
    path.write_text(
        json.dumps({
            "schema_version": "1.0",
            "artifact_sha256": "a" * 64,
            "publisher_age_days": 3,
            "publisher_skill_count": 1,
            "exact_artifact_malicious": False,
        }),
        encoding="utf-8",
    )

    context = load_ecosystem_context(path, "a" * 64)

    assert context.publisher_age_days == 3
    with pytest.raises(ValueError, match="does not match"):
        load_ecosystem_context(path, "b" * 64)


def test_malicious_intelligence_requires_attributed_source(tmp_path):
    path = tmp_path / "context.json"
    path.write_text(
        json.dumps({
            "schema_version": "1.0",
            "artifact_sha256": "a" * 64,
            "exact_artifact_malicious": True,
        }),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="requires a source"):
        load_ecosystem_context(path, "a" * 64)
