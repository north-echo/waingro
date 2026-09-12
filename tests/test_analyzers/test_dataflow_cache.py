"""Regression coverage for bounded per-scan dataflow preparation."""

from pathlib import Path

from waingro.analyzers.dataflow import statement_for_finding
from waingro.models import BundledFileContent, ParsedSkill, SkillMetadata


class CountingText(str):
    """Track whole-content line splitting without relying on wall-clock timing."""

    split_calls = 0

    def splitlines(self, *args, **kwargs):
        type(self).split_calls += 1
        return super().splitlines(*args, **kwargs)


def test_repeated_findings_reuse_per_skill_file_analysis(tmp_path: Path) -> None:
    bundled_path = tmp_path / "references" / "dataset.json"
    content = CountingText('{"endpoint": "https://example.test"}\n')
    skill = ParsedSkill(
        path=tmp_path,
        metadata=SkillMetadata(name="cache-test", description=None, version=None, author=None),
        body="",
        bundled_content=[BundledFileContent(path=bundled_path, content=content)],
    )

    CountingText.split_calls = 0
    assert statement_for_finding(skill, bundled_path, 1) == content.rstrip()
    initial_calls = CountingText.split_calls
    assert initial_calls == 2

    assert statement_for_finding(skill, bundled_path, 1) == content.rstrip()
    assert CountingText.split_calls == initial_calls
