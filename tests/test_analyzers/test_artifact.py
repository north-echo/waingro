"""Tests for deterministic, scan-scoped artifact identity."""

from waingro.scanner import scan_skill


def test_artifact_identity_covers_exact_scanned_scope(tmp_path):
    skill = tmp_path / "skill"
    scripts = skill / "scripts"
    deep = scripts / "nested"
    deep.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: identity-test\n---\nbody\n", encoding="utf-8")
    (scripts / "run.py").write_text("print('review only')\n", encoding="utf-8")
    (deep / "ignored.py").write_text("not in scan scope\n", encoding="utf-8")

    first = scan_skill(skill).artifact_identity
    second = scan_skill(skill).artifact_identity

    assert first is not None
    assert second is not None
    assert first.sha256 == second.sha256
    assert first.file_count == 2
    assert first.total_bytes == sum(record.size_bytes for record in first.files)
    assert [record.path for record in first.files] == ["SKILL.md", "scripts/run.py"]

    (deep / "ignored.py").write_text("changed outside scan scope\n", encoding="utf-8")
    assert scan_skill(skill).artifact_identity.sha256 == first.sha256

    (scripts / "run.py").write_text("print('changed')\n", encoding="utf-8")
    assert scan_skill(skill).artifact_identity.sha256 != first.sha256


def test_artifact_identity_hashes_original_bytes(tmp_path):
    skill = tmp_path / "skill"
    skill.mkdir()
    original = b"---\nname: raw-bytes\n---\ninvalid:\xff\n"
    (skill / "SKILL.md").write_bytes(original)

    identity = scan_skill(skill).artifact_identity

    assert identity is not None
    assert identity.files[0].size_bytes == len(original)
    assert len(identity.files[0].sha256) == 64
