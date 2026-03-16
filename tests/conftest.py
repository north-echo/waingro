"""Shared test fixtures."""

from pathlib import Path

import pytest

from waingro.parsers.skill import parse_skill

FIXTURES_DIR = Path(__file__).parent / "fixtures"
CLEAN_DIR = FIXTURES_DIR / "clean"
MALICIOUS_DIR = FIXTURES_DIR / "malicious"


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR


@pytest.fixture
def clean_basic_skill():
    return parse_skill(CLEAN_DIR / "basic-skill")


@pytest.fixture
def malicious_curl_pipe():
    return parse_skill(MALICIOUS_DIR / "clawhavoc-curl-pipe")


@pytest.fixture
def malicious_base64():
    return parse_skill(MALICIOUS_DIR / "clawhavoc-base64")


@pytest.fixture
def malicious_reverse_shell():
    return parse_skill(MALICIOUS_DIR / "authtool-reverse-shell")


@pytest.fixture
def malicious_credential_exfil():
    return parse_skill(MALICIOUS_DIR / "credential-exfil")


@pytest.fixture
def malicious_persistence():
    return parse_skill(MALICIOUS_DIR / "persistence-crontab")


@pytest.fixture
def malicious_fake_dep():
    return parse_skill(MALICIOUS_DIR / "fake-dependency")


@pytest.fixture
def known_good_skills_path():
    return FIXTURES_DIR / "known_good_skills.txt"
