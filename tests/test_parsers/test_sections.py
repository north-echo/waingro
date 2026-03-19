"""Tests for markdown section parser."""

from waingro.parsers.sections import classify_heading, find_section_for_line, parse_sections


def test_parse_basic_sections():
    body = "# Title\n\nIntro text.\n\n## Usage\n\nDo this.\n\n## Config\n\nSet that."
    sections = parse_sections(body)
    assert len(sections) == 3
    assert sections[0].heading == "Title"
    assert sections[0].level == 1
    assert sections[1].heading == "Usage"
    assert sections[1].level == 2
    assert sections[2].heading == "Config"


def test_classify_detection_heading():
    assert classify_heading("What It Detects") == "detection"
    assert classify_heading("## Blocked Patterns") == "detection"
    assert classify_heading("Threat Categories") == "detection"
    assert classify_heading("BLACKLIST_PATTERNS") == "detection"
    assert classify_heading("Instant Block") == "detection"


def test_classify_usage_heading():
    assert classify_heading("Usage") == "usage"
    assert classify_heading("Quick Start") == "usage"
    assert classify_heading("How It Works") == "usage"
    assert classify_heading("Installation") == "usage"


def test_classify_documentation_heading():
    assert classify_heading("Overview") == "documentation"
    assert classify_heading("Features") == "documentation"
    assert classify_heading("About") == "documentation"


def test_classify_configuration_heading():
    assert classify_heading("Configuration") == "configuration"
    assert classify_heading("Settings") == "configuration"


def test_classify_unknown_heading():
    assert classify_heading("Random Stuff") == "unknown"
    assert classify_heading("Credits") == "unknown"


def test_parent_heading_tracking():
    body = "# Top\n\n## Child\n\n### Grandchild\n\nContent."
    sections = parse_sections(body)
    assert sections[0].parent_heading is None
    assert sections[1].parent_heading == "Top"
    assert sections[2].parent_heading == "Child"


def test_find_section_for_line():
    body = "# Title\n\nLine 2.\n\n## Usage\n\nLine 6.\n\n## Config\n\nLine 10."
    sections = parse_sections(body)
    assert find_section_for_line(sections, 1).heading == "Title"
    assert find_section_for_line(sections, 6).heading == "Usage"
    assert find_section_for_line(sections, 10).heading == "Config"


def test_find_section_returns_none_before_first_heading():
    sections = parse_sections("# First\n\nContent.")
    assert find_section_for_line(sections, 0) is None


def test_section_offset():
    body = "## Heading\n\nContent."
    sections = parse_sections(body, start_line_offset=10)
    assert sections[0].start_line == 11


def test_security_tool_body_sections(make_inline_skill):
    """Verify sections are populated in ParsedSkill after parsing."""
    from pathlib import Path

    from waingro.parsers.skill import parse_skill

    # Use an existing fixture
    fixture = Path(__file__).parent.parent / "fixtures" / "skills" / "benign" / "weather-checker"
    skill = parse_skill(fixture)
    assert len(skill.sections) > 0
    assert any(s.heading for s in skill.sections)
