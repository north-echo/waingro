"""Tests for provenance identity normalization."""

from waingro.resolvers.provenance import github_repository_slug


def test_normalizes_supported_github_repository_urls():
    assert github_repository_slug("git+https://github.com/example/project.git") == "example/project"
    assert github_repository_slug("git@github.com:example/project.git") == "example/project"


def test_rejects_non_github_or_non_repository_identity():
    assert github_repository_slug("https://example.com/example/project") is None
    assert github_repository_slug("https://github.com/example") is None
