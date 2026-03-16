"""Tests for typosquat detection."""

from pathlib import Path

from waingro.analyzers.typosquat import _levenshtein, check_typosquat, load_known_good_skills

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def test_levenshtein_identical():
    assert _levenshtein("test", "test") == 0


def test_levenshtein_one_off():
    assert _levenshtein("test", "tset") == 2  # transposition = 2 ops
    assert _levenshtein("test", "tест") >= 1


def test_levenshtein_single_char():
    assert _levenshtein("weather-check", "weather-checc") == 1


def test_load_known_good():
    skills = load_known_good_skills(FIXTURES_DIR / "known_good_skills.txt")
    assert "weather-check" in skills
    assert len(skills) > 5


def test_typosquat_match():
    findings = check_typosquat("weather-checc", ["weather-check"])
    assert len(findings) == 1
    assert findings[0].rule_id == "TYPO-001"


def test_typosquat_exact_no_match():
    findings = check_typosquat("weather-check", ["weather-check"])
    assert len(findings) == 0


def test_typosquat_no_match():
    findings = check_typosquat("totally-different", ["weather-check"])
    assert len(findings) == 0
