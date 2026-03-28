"""Batch scan pipeline: clone repos, scan, aggregate results."""

import json
import logging
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from waingro.mcp.discovery import MCPServerEntry, load_manifest
from waingro.mcp.models import Severity
from waingro.mcp.scanner import scan_server

logger = logging.getLogger(__name__)

CLONE_TIMEOUT = 60  # seconds per clone
SCAN_TIMEOUT = 120  # seconds per scan (enforced via alarm)


@dataclass
class BatchConfig:
    manifest_path: Path
    clone_dir: Path
    results_path: Path
    max_servers: int = 0  # 0 = all
    skip_existing: bool = True
    cleanup_after_scan: bool = False  # delete cloned repo after scanning
    min_stars: int = 0  # only scan repos with >= N stars (0 = all)
    github_only: bool = False  # only scan GitHub-sourced entries


@dataclass
class ServerScanSummary:
    name: str
    url: str | None
    source: str
    stars: int | None
    language: str | None
    verdict: str
    files_scanned: int
    tools_found: int
    rules_evaluated: int
    finding_count: int
    critical_count: int
    high_count: int
    medium_count: int
    findings: list[dict] = field(default_factory=list)
    error: str | None = None
    scan_duration_ms: int = 0


@dataclass
class BatchResult:
    total_discovered: int
    total_cloned: int
    total_scanned: int
    total_failed: int
    total_findings: int
    verdict_counts: dict = field(default_factory=dict)
    severity_counts: dict = field(default_factory=dict)
    rule_hit_counts: dict = field(default_factory=dict)
    servers: list[ServerScanSummary] = field(default_factory=list)


def _clone_repo(url: str, dest: Path) -> bool:
    """Shallow clone a GitHub repo. Returns True on success."""
    if dest.exists():
        return True

    # Normalize URL to .git
    git_url = url.rstrip("/")
    if not git_url.endswith(".git"):
        git_url += ".git"

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", "--quiet", git_url, str(dest)],
            timeout=CLONE_TIMEOUT,
            capture_output=True,
            text=True,
        )
        return dest.exists()
    except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
        logger.debug("Clone failed for %s: %s", url, e)
        return False


def _url_to_dirname(url: str) -> str:
    """Convert a GitHub URL to a safe directory name."""
    # https://github.com/owner/repo -> owner__repo
    clean = url.rstrip("/")
    clean = clean.replace("https://github.com/", "")
    clean = clean.replace("/", "__")
    clean = clean.replace(".git", "")
    # Sanitize
    return "".join(c if c.isalnum() or c in ("_", "-", ".") else "_" for c in clean)


def _find_scannable_dir(clone_path: Path) -> Path:
    """Find the best directory to scan within a cloned repo.

    Some repos have the MCP server in a subdirectory (src/, server/, etc.)
    """
    # Check if root has package.json/pyproject.toml with MCP references
    for manifest in ("package.json", "pyproject.toml"):
        mp = clone_path / manifest
        if mp.exists():
            try:
                content = mp.read_text(encoding="utf-8").lower()
                if "mcp" in content or "modelcontextprotocol" in content:
                    return clone_path
            except OSError:
                pass

    # Check common subdirectories
    for subdir in ("src", "server", "mcp-server", "packages/server"):
        sd = clone_path / subdir
        if sd.is_dir():
            for manifest in ("package.json", "pyproject.toml"):
                if (sd / manifest).exists():
                    return sd

    # Fallback to root
    return clone_path


def run_batch_scan(config: BatchConfig) -> BatchResult:
    """Run batch clone + scan pipeline."""
    config.clone_dir.mkdir(parents=True, exist_ok=True)

    # Load manifest
    entries = load_manifest(config.manifest_path)
    total_discovered = len(entries)

    # Filter
    if config.github_only:
        entries = [e for e in entries if e.url and "github.com" in e.url]
    if config.min_stars > 0:
        entries = [e for e in entries if (e.stars or 0) >= config.min_stars]
    if config.max_servers > 0:
        entries = entries[:config.max_servers]

    print(f"Batch scan: {len(entries)} servers selected from {total_discovered} discovered")

    result = BatchResult(
        total_discovered=total_discovered,
        total_cloned=0,
        total_scanned=0,
        total_failed=0,
        total_findings=0,
    )

    for i, entry in enumerate(entries):
        pct = (i + 1) / len(entries) * 100
        print(f"[{i+1}/{len(entries)} {pct:.0f}%] {entry.name}...", end=" ", flush=True)

        summary = _scan_entry(entry, config)
        result.servers.append(summary)

        if summary.error:
            result.total_failed += 1
            print(f"FAILED: {summary.error}")
        else:
            result.total_scanned += 1
            result.total_findings += summary.finding_count

            # Track verdicts
            v = summary.verdict
            result.verdict_counts[v] = result.verdict_counts.get(v, 0) + 1

            # Track severities
            result.severity_counts["critical"] = result.severity_counts.get("critical", 0) + summary.critical_count
            result.severity_counts["high"] = result.severity_counts.get("high", 0) + summary.high_count
            result.severity_counts["medium"] = result.severity_counts.get("medium", 0) + summary.medium_count

            # Track rule hits
            for f in summary.findings:
                rid = f["rule_id"]
                result.rule_hit_counts[rid] = result.rule_hit_counts.get(rid, 0) + 1

            verdict_str = summary.verdict
            if summary.finding_count > 0:
                print(f"{verdict_str} ({summary.finding_count} findings, {summary.tools_found} tools)")
            else:
                print(f"{verdict_str}")

        if summary.error and summary.error == "clone_failed":
            pass  # Don't count as cloned
        else:
            result.total_cloned += 1

    # Save results
    _save_results(result, config.results_path)
    _print_summary(result)

    return result


def _scan_entry(entry: MCPServerEntry, config: BatchConfig) -> ServerScanSummary:
    """Clone and scan a single entry."""
    if not entry.url or "github.com" not in entry.url:
        return ServerScanSummary(
            name=entry.name, url=entry.url, source=entry.source,
            stars=entry.stars, language=entry.language,
            verdict="SKIPPED", files_scanned=0, tools_found=0,
            rules_evaluated=0, finding_count=0, critical_count=0,
            high_count=0, medium_count=0, error="no_github_url",
        )

    dirname = _url_to_dirname(entry.url)
    clone_path = config.clone_dir / dirname

    # Clone
    if not clone_path.exists():
        if not _clone_repo(entry.url, clone_path):
            return ServerScanSummary(
                name=entry.name, url=entry.url, source=entry.source,
                stars=entry.stars, language=entry.language,
                verdict="SKIPPED", files_scanned=0, tools_found=0,
                rules_evaluated=0, finding_count=0, critical_count=0,
                high_count=0, medium_count=0, error="clone_failed",
            )

    # Find scannable directory
    scan_path = _find_scannable_dir(clone_path)

    # Scan
    t0 = time.monotonic()
    try:
        scan_result = scan_server(scan_path)
    except Exception as e:
        return ServerScanSummary(
            name=entry.name, url=entry.url, source=entry.source,
            stars=entry.stars, language=entry.language,
            verdict="ERROR", files_scanned=0, tools_found=0,
            rules_evaluated=0, finding_count=0, critical_count=0,
            high_count=0, medium_count=0,
            error=f"scan_error: {type(e).__name__}: {str(e)[:200]}",
        )
    duration_ms = int((time.monotonic() - t0) * 1000)

    # Build findings list
    findings_data = []
    for f in scan_result.findings:
        findings_data.append({
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity.value,
            "category": f.category.value,
            "file": str(f.file_path),
            "line": f.line_number,
            "matched": f.matched_content[:200],
            "confidence": f.confidence,
            "context_note": f.context_note,
            "reference": f.reference,
        })

    critical = sum(1 for f in scan_result.findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in scan_result.findings if f.severity == Severity.HIGH)
    medium = sum(1 for f in scan_result.findings if f.severity == Severity.MEDIUM)

    # Cleanup if configured
    if config.cleanup_after_scan and clone_path.exists():
        shutil.rmtree(clone_path, ignore_errors=True)

    return ServerScanSummary(
        name=entry.name,
        url=entry.url,
        source=entry.source,
        stars=entry.stars,
        language=entry.language,
        verdict=scan_result.verdict,
        files_scanned=scan_result.files_scanned,
        tools_found=len(scan_result.metadata.tools),
        rules_evaluated=scan_result.rules_evaluated,
        finding_count=len(scan_result.findings),
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        findings=findings_data,
        scan_duration_ms=duration_ms,
    )


def _save_results(result: BatchResult, path: Path):
    """Save batch results as JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)

    output = {
        "summary": {
            "total_discovered": result.total_discovered,
            "total_cloned": result.total_cloned,
            "total_scanned": result.total_scanned,
            "total_failed": result.total_failed,
            "total_findings": result.total_findings,
            "verdict_counts": result.verdict_counts,
            "severity_counts": result.severity_counts,
            "rule_hit_counts": dict(sorted(result.rule_hit_counts.items(), key=lambda x: -x[1])),
        },
        "servers": [
            {
                "name": s.name,
                "url": s.url,
                "source": s.source,
                "stars": s.stars,
                "language": s.language,
                "verdict": s.verdict,
                "files_scanned": s.files_scanned,
                "tools_found": s.tools_found,
                "rules_evaluated": s.rules_evaluated,
                "finding_count": s.finding_count,
                "critical_count": s.critical_count,
                "high_count": s.high_count,
                "medium_count": s.medium_count,
                "findings": s.findings,
                "error": s.error,
                "scan_duration_ms": s.scan_duration_ms,
            }
            for s in result.servers
        ],
    }

    path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"\nResults saved to {path}")


def _print_summary(result: BatchResult):
    """Print batch scan summary to console."""
    print(f"\n{'='*60}")
    print(f"WAINGRO-MCP Batch Scan Summary")
    print(f"{'='*60}")
    print(f"Discovered:  {result.total_discovered}")
    print(f"Cloned:      {result.total_cloned}")
    print(f"Scanned:     {result.total_scanned}")
    print(f"Failed:      {result.total_failed}")
    print(f"Findings:    {result.total_findings}")
    print()

    print("Verdicts:")
    for v in ("MALICIOUS", "SUSPICIOUS", "WARNING", "REVIEW", "CLEAN"):
        count = result.verdict_counts.get(v, 0)
        if count > 0:
            print(f"  {v:12s} {count}")

    print()
    print("Severity breakdown:")
    for sev in ("critical", "high", "medium"):
        count = result.severity_counts.get(sev, 0)
        if count > 0:
            print(f"  {sev:12s} {count}")

    print()
    print("Top rule hits:")
    sorted_rules = sorted(result.rule_hit_counts.items(), key=lambda x: -x[1])
    for rid, count in sorted_rules[:15]:
        print(f"  {rid:10s} {count}")
