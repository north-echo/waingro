"""Tests for skill parser."""

from pathlib import Path

from waingro.parsers.skill import (
    discover_bundled_files,
    extract_code_blocks,
    parse_frontmatter,
    parse_skill,
)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def test_parse_frontmatter():
    content = '---\nname: "test"\nversion: "1.0"\n---\n\n# Body\n'
    meta, body = parse_frontmatter(content)
    assert meta["name"] == "test"
    assert meta["version"] == "1.0"
    assert "# Body" in body


def test_parse_frontmatter_missing():
    content = "# No frontmatter\n\nJust body."
    meta, body = parse_frontmatter(content)
    assert meta == {}
    assert "# No frontmatter" in body


def test_parse_frontmatter_scalar_is_treated_as_invalid():
    meta, body = parse_frontmatter("---\njust a string\n---\nbody\n")
    assert meta == {}
    assert body == "body\n"


def test_parse_frontmatter_recovers_standard_fields_from_invalid_yaml():
    content = """---
name: prompt-guard
description: Detect attacks. Trigger on: prompt injection
tags: [security, detection]
metadata:
  privileged: true
---
# Prompt Guard
"""

    meta, body = parse_frontmatter(content)

    assert meta == {
        "name": "prompt-guard",
        "description": "Detect attacks. Trigger on: prompt injection",
        "tags": ["security", "detection"],
    }
    assert body == "# Prompt Guard\n"


def test_extract_code_blocks():
    content = "text\n```bash\necho hello\n```\nmore text\n```python\nprint('hi')\n```\n"
    blocks = extract_code_blocks(content)
    assert len(blocks) == 2
    assert blocks[0]["language"] == "bash"
    assert blocks[0]["content"] == "echo hello"
    assert blocks[1]["language"] == "python"
    assert blocks[1]["content"] == "print('hi')"


def test_parse_clean_skill():
    skill = parse_skill(FIXTURES_DIR / "clean" / "basic-skill")
    assert skill.metadata.name == "weather-check"
    assert skill.metadata.version == "1.0.0"
    assert skill.metadata.author == "example-dev"
    assert "weather" in skill.metadata.tags
    assert "Weather Check" in skill.body


def test_parse_malicious_skill():
    skill = parse_skill(FIXTURES_DIR / "malicious" / "clawhavoc-curl-pipe")
    assert skill.metadata.name == "solana-wallet-tracker"
    assert len(skill.code_blocks) >= 1
    assert "curl" in skill.code_blocks[0]["content"]


def test_non_string_metadata_fields_are_normalized(tmp_path):
    skill_dir = tmp_path / "fallback-name"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: null\ndescription: 42\ntags: [security, null, 5]\ntools: bash\n---\nbody\n",
        encoding="utf-8",
    )
    skill = parse_skill(skill_dir)
    assert skill.metadata.name == "fallback-name"
    assert skill.metadata.description is None
    assert skill.metadata.tags == ["security"]
    assert skill.metadata.tools == ["bash"]


def test_bundled_discovery_ignores_directories_with_script_suffix(tmp_path):
    (tmp_path / "hash.js").mkdir()
    script = tmp_path / "real.js"
    script.write_text("console.log('ok')\n", encoding="utf-8")
    assert discover_bundled_files(tmp_path) == [script]


def test_bundled_discovery_does_not_follow_external_file_symlink(tmp_path):
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("secret = 'outside'\n", encoding="utf-8")
    (skill_dir / "linked.py").symlink_to(outside)
    assert discover_bundled_files(skill_dir) == []


def test_bundled_discovery_does_not_follow_symlinked_directory(tmp_path):
    skill_dir = tmp_path / "skill"
    real_dir = skill_dir / "real"
    real_dir.mkdir(parents=True)
    script = real_dir / "run.py"
    script.write_text("print('safe')\n", encoding="utf-8")
    (skill_dir / "linked").symlink_to(real_dir, target_is_directory=True)

    assert discover_bundled_files(skill_dir) == [script]


def test_bundled_discovery_includes_instruction_and_script_formats(tmp_path):
    references = tmp_path / "references"
    references.mkdir()
    markdown = references / "policy.md"
    typescript = tmp_path / "handler.ts"
    markdown.write_text("instructions\n", encoding="utf-8")
    typescript.write_text("export const value = 1;\n", encoding="utf-8")

    assert set(discover_bundled_files(tmp_path)) == {markdown, typescript}


def test_bundled_discovery_stops_after_two_levels(tmp_path):
    included_dir = tmp_path / "references"
    excluded_dir = included_dir / "nested"
    excluded_dir.mkdir(parents=True)
    included = included_dir / "policy.md"
    excluded = excluded_dir / "fixture.md"
    included.write_text("included\n", encoding="utf-8")
    excluded.write_text("excluded\n", encoding="utf-8")

    assert discover_bundled_files(tmp_path) == [included]


def test_bundled_discovery_does_not_rescan_case_variant_manifest(tmp_path):
    manifest = tmp_path / "skill.md"
    manifest.write_text("instructions\n", encoding="utf-8")

    assert discover_bundled_files(tmp_path) == []


def test_parse_skill_rejects_directory_without_manifest(tmp_path):
    try:
        parse_skill(tmp_path)
    except FileNotFoundError as exc:
        assert "SKILL.md not found" in str(exc)
    else:
        raise AssertionError("missing SKILL.md should not scan as an empty clean skill")


def test_parse_skill_rejects_arbitrary_file(tmp_path):
    other = tmp_path / "README.md"
    other.write_text("not a skill\n", encoding="utf-8")
    try:
        parse_skill(other)
    except ValueError as exc:
        assert "expected a skill directory or SKILL.md" in str(exc)
    else:
        raise AssertionError("an arbitrary file should not be treated as SKILL.md")


def test_parse_skill_rejects_symlinked_manifest(tmp_path):
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    target = tmp_path / "outside.md"
    target.write_text("---\nname: outside\n---\n", encoding="utf-8")
    (skill_dir / "SKILL.md").symlink_to(target)

    try:
        parse_skill(skill_dir)
    except ValueError as exc:
        assert "symlinked SKILL.md" in str(exc)
    else:
        raise AssertionError("a symlinked manifest must not be followed")


def test_parse_skill_rejects_symlinked_directory(tmp_path):
    target = tmp_path / "real-skill"
    target.mkdir()
    (target / "SKILL.md").write_text("---\nname: real\n---\n", encoding="utf-8")
    link = tmp_path / "linked-skill"
    link.symlink_to(target, target_is_directory=True)

    try:
        parse_skill(link)
    except ValueError as exc:
        assert "symlinked skill paths" in str(exc)
    else:
        raise AssertionError("a symlinked skill directory must not be followed")
