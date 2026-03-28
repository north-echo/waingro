"""Discovery pipeline: enumerate MCP servers from multiple sources."""

import json
import re
import subprocess
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class MCPServerEntry:
    """A discovered MCP server entry."""
    name: str
    source: str  # "npm", "github", "awesome-list"
    url: str | None = None
    npm_package: str | None = None
    description: str | None = None
    stars: int | None = None
    language: str | None = None
    last_updated: str | None = None
    cloned_path: Path | None = None


def discover_from_awesome_list(readme_path: Path) -> list[MCPServerEntry]:
    """Parse awesome-mcp-servers README.md for GitHub repo links."""
    if not readme_path.exists():
        return []

    content = readme_path.read_text(encoding="utf-8")
    entries = []
    seen_urls = set()

    # Match markdown links to GitHub repos: [Name](https://github.com/owner/repo)
    link_re = re.compile(
        r"\*?\*?\[([^\]]+)\]\((https://github\.com/[^/]+/[^/)]+)\)"
    )

    for m in link_re.finditer(content):
        name = m.group(1).strip("*")
        url = m.group(2).rstrip("/")

        if url in seen_urls:
            continue
        seen_urls.add(url)

        # Get description: text after the link on the same line
        line_end = content.find("\n", m.end())
        desc_text = content[m.end():line_end].strip(" -–—") if line_end > 0 else None

        entries.append(MCPServerEntry(
            name=name,
            source="awesome-list",
            url=url,
            description=desc_text[:200] if desc_text else None,
        ))

    return entries


def discover_from_npm(keywords: list[str] | None = None, limit: int = 250) -> list[MCPServerEntry]:
    """Search npm registry for MCP server packages.

    Uses the npm search API endpoint.
    """
    if keywords is None:
        keywords = ["mcp-server", "@modelcontextprotocol"]

    entries = []
    seen = set()

    for keyword in keywords:
        url = f"https://registry.npmjs.org/-/v1/search?text={keyword}&size={limit}"
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
            print(f"  Warning: npm search for '{keyword}' failed: {e}")
            continue

        for obj in data.get("objects", []):
            pkg = obj.get("package", {})
            name = pkg.get("name", "")
            if name in seen:
                continue
            seen.add(name)

            # Get repo URL
            repo = pkg.get("links", {}).get("repository", "")
            npm_url = pkg.get("links", {}).get("npm", "")

            entries.append(MCPServerEntry(
                name=name,
                source="npm",
                url=repo or npm_url or f"https://www.npmjs.com/package/{name}",
                npm_package=name,
                description=pkg.get("description", "")[:200],
            ))

    return entries


def discover_from_github(
    topics: list[str] | None = None,
    max_pages: int = 3,
    per_page: int = 100,
) -> list[MCPServerEntry]:
    """Search GitHub for MCP server repositories by topic.

    Uses the GitHub search API (unauthenticated = 10 req/min rate limit).
    """
    if topics is None:
        topics = ["mcp-server", "model-context-protocol", "mcp"]

    entries = []
    seen_urls = set()

    for topic in topics:
        for page in range(1, max_pages + 1):
            url = (
                f"https://api.github.com/search/repositories?"
                f"q=topic:{topic}&sort=stars&per_page={per_page}&page={page}"
            )
            try:
                req = urllib.request.Request(url, headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "waingro-mcp-scanner",
                })
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read())
            except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
                print(f"  Warning: GitHub search for topic '{topic}' page {page} failed: {e}")
                break

            items = data.get("items", [])
            if not items:
                break

            for repo in items:
                html_url = repo.get("html_url", "")
                if html_url in seen_urls:
                    continue
                seen_urls.add(html_url)

                entries.append(MCPServerEntry(
                    name=repo.get("full_name", repo.get("name", "")),
                    source="github",
                    url=html_url,
                    description=repo.get("description", "")[:200] if repo.get("description") else None,
                    stars=repo.get("stargazers_count"),
                    language=repo.get("language"),
                    last_updated=repo.get("pushed_at"),
                ))

    return entries


def deduplicate(entries: list[MCPServerEntry]) -> list[MCPServerEntry]:
    """Deduplicate entries by normalized GitHub URL."""
    seen = {}
    for entry in entries:
        key = _normalize_url(entry.url) if entry.url else entry.name.lower()
        if key not in seen:
            seen[key] = entry
        else:
            # Merge: prefer entry with more metadata
            existing = seen[key]
            if entry.stars and not existing.stars:
                existing.stars = entry.stars
            if entry.npm_package and not existing.npm_package:
                existing.npm_package = entry.npm_package
            if entry.language and not existing.language:
                existing.language = entry.language
            # Add source
            if entry.source not in existing.source:
                existing.source += f"+{entry.source}"
    return list(seen.values())


def _normalize_url(url: str) -> str:
    """Normalize GitHub URL for deduplication."""
    url = url.lower().rstrip("/")
    url = re.sub(r"\.git$", "", url)
    url = re.sub(r"^https?://github\.com/", "", url)
    # Strip tree/main/src/... suffixes
    url = re.sub(r"/tree/.*$", "", url)
    url = re.sub(r"/blob/.*$", "", url)
    return url


def run_discovery(
    awesome_readme: Path | None = None,
    include_npm: bool = True,
    include_github: bool = True,
    output_path: Path | None = None,
) -> list[MCPServerEntry]:
    """Run full discovery pipeline and return deduplicated entries."""
    all_entries = []

    if awesome_readme:
        print(f"[1/3] Parsing awesome-mcp-servers list...")
        awesome = discover_from_awesome_list(awesome_readme)
        print(f"  Found {len(awesome)} entries from awesome list")
        all_entries.extend(awesome)

    if include_npm:
        print(f"[2/3] Searching npm registry...")
        npm = discover_from_npm()
        print(f"  Found {len(npm)} entries from npm")
        all_entries.extend(npm)

    if include_github:
        print(f"[3/3] Searching GitHub topics...")
        gh = discover_from_github()
        print(f"  Found {len(gh)} entries from GitHub")
        all_entries.extend(gh)

    deduped = deduplicate(all_entries)
    print(f"\nTotal after deduplication: {len(deduped)} unique MCP servers")

    if output_path:
        _save_manifest(deduped, output_path)
        print(f"Manifest saved to {output_path}")

    return deduped


def _save_manifest(entries: list[MCPServerEntry], path: Path) -> None:
    """Save discovery manifest as JSON."""
    data = []
    for e in entries:
        data.append({
            "name": e.name,
            "source": e.source,
            "url": e.url,
            "npm_package": e.npm_package,
            "description": e.description,
            "stars": e.stars,
            "language": e.language,
            "last_updated": e.last_updated,
        })
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_manifest(path: Path) -> list[MCPServerEntry]:
    """Load a previously saved discovery manifest."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return [
        MCPServerEntry(
            name=d["name"],
            source=d["source"],
            url=d.get("url"),
            npm_package=d.get("npm_package"),
            description=d.get("description"),
            stars=d.get("stars"),
            language=d.get("language"),
            last_updated=d.get("last_updated"),
        )
        for d in data
    ]
