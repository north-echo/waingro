"""Tests for skill parser."""

from pathlib import Path

from waingro.parsers.skill import extract_code_blocks, parse_frontmatter, parse_skill

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
