#!/usr/bin/env python3
"""Split flagged skills into priority triage tiers and extract EXEC-001 domains.

Usage:
    python scripts/triage_prep.py \
        --flagged ~/clawhub-corpus/audit_results_v2/flagged_skills.json \
        --findings ~/clawhub-corpus/audit_results_v2/all_findings.jsonl \
        --output-dir ~/clawhub-corpus/audit_results_v2/triage_tiers/
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlparse

# --- Domain classification for EXEC-001 filtering ---

KNOWN_SAFE_DOMAINS = {
    "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
    "gist.githubusercontent.com", "api.github.com",
    "brew.sh", "formulae.brew.sh",
    "nodejs.org", "npmjs.com", "registry.npmjs.org", "deb.nodesource.com",
    "pypi.org", "files.pythonhosted.org", "bootstrap.pypa.io",
    "rust-lang.org", "rustup.rs", "static.rust-lang.org",
    "get.docker.com", "download.docker.com",
    "deno.land",
    "bun.sh",
    "releases.hashicorp.com",
    "dl.google.com", "packages.cloud.google.com", "storage.googleapis.com",
    "apt.llvm.org", "apt.releases.hashicorp.com",
    "packages.microsoft.com", "aka.ms",
    "install.python-poetry.org", "astral.sh",
    "sh.rustup.rs",
    "cli.github.com",
    "getcomposer.org",
    "get.helm.sh",
    "baltocdn.com",
    "mise.jdx.dev", "mise.run",
    "starship.rs",
    "ohmyz.sh", "ohmyposh.dev",
    "sdkman.io", "get.sdkman.io",
    "install.julialang.org",
    "repo.anaconda.com",
    "rpm.nodesource.com",
    "gitlab.com",
}

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq"}

URL_SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}

SUSPICIOUS_PATH_PATTERNS = re.compile(
    r"/payload|/setup\.sh|/install\.sh|/x$|/run$|/exec|/beacon|/c2|/shell",
    re.IGNORECASE,
)

URL_RE = re.compile(r"https?://[^\s\"'|>]+")
IP_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

# Rules that define Tier 4 (noise) — if these are the ONLY rules on a skill, skip it
NOISE_RULES = {"OBFUSC-001", "EXFIL-001", "EXFIL-004", "SOCIAL-001", "PERSIST-004"}


def extract_domain(matched_content: str) -> str | None:
    """Extract domain from a curl/wget matched content string."""
    m = URL_RE.search(matched_content)
    if not m:
        return None
    try:
        parsed = urlparse(m.group(0))
        return parsed.hostname
    except Exception:
        return None


def classify_domain(domain: str | None, url: str | None = None) -> str:
    """Classify a domain as known-safe, suspicious, or unknown."""
    if domain is None:
        return "unparseable"

    # Check known-safe list
    if domain in KNOWN_SAFE_DOMAINS:
        return "known-safe"
    # Check if it's a subdomain of a known-safe domain
    for safe in KNOWN_SAFE_DOMAINS:
        if domain.endswith("." + safe):
            return "known-safe"

    # Check URL shorteners
    if domain in URL_SHORTENERS:
        return "suspicious"

    # Check suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return "suspicious"

    # Check if it's an IP address
    if IP_RE.fullmatch(domain):
        return "suspicious"

    # Check suspicious path patterns in URL
    if url and SUSPICIOUS_PATH_PATTERNS.search(url):
        return "suspicious"

    # Check HTTP (not HTTPS)
    if url and url.startswith("http://"):
        return "suspicious"

    return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser(description="Split flagged skills into triage tiers")
    parser.add_argument("--flagged", type=Path, required=True)
    parser.add_argument("--findings", type=Path, help="(unused, kept for CLI compat)")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    flagged_path = args.flagged.expanduser().resolve()
    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load flagged skills
    with flagged_path.open() as f:
        flagged_skills = json.load(f)

    # Index by slug for quick lookup
    skills_by_slug: dict[str, dict] = {}
    for skill in flagged_skills:
        slug = skill["skill_slug"]
        # Keep the one with more findings if duplicate slugs
        existing = skills_by_slug.get(slug)
        if not existing or skill["finding_count"] > existing["finding_count"]:
            skills_by_slug[slug] = skill

    # Build rule_ids set per skill
    skill_rules: dict[str, set[str]] = {}
    for slug, skill in skills_by_slug.items():
        skill_rules[slug] = {f["rule_id"] for f in skill["findings"]}

    # --- Tier 1 ---
    tier1_c2 = []
    tier1_revshell = []
    tier1_jailbreak = []
    tier1_slugs: set[str] = set()

    for slug, rules in skill_rules.items():
        if "NET-002" in rules:
            tier1_c2.append(skills_by_slug[slug])
            tier1_slugs.add(slug)
        if "NET-001" in rules:
            tier1_revshell.append(skills_by_slug[slug])
            tier1_slugs.add(slug)
        if "INJECT-002" in rules:
            tier1_jailbreak.append(skills_by_slug[slug])
            tier1_slugs.add(slug)

    # --- Tier 2: EXEC-001 (not already in Tier 1) ---
    tier2_all = []
    tier2_slugs: set[str] = set()
    for slug, rules in skill_rules.items():
        if "EXEC-001" in rules and slug not in tier1_slugs:
            tier2_all.append(skills_by_slug[slug])
            tier2_slugs.add(slug)

    # Domain extraction and filtering for Tier 2
    domain_freq: dict[str, int] = {}
    domain_classification: dict[str, str] = {}
    skill_domains: dict[str, list[dict]] = {}  # slug -> list of domain info

    for skill in tier2_all:
        slug = skill["skill_slug"]
        skill_domains[slug] = []
        for finding in skill["findings"]:
            if finding["rule_id"] != "EXEC-001":
                continue
            matched = finding["matched_content"]
            url_match = URL_RE.search(matched)
            url = url_match.group(0) if url_match else None
            domain = extract_domain(matched)
            classification = classify_domain(domain, url)

            if domain:
                domain_freq[domain] = domain_freq.get(domain, 0) + 1
                domain_classification[domain] = classification

            skill_domains[slug].append({
                "domain": domain,
                "url": url,
                "classification": classification,
                "matched_content": matched,
            })

    # Second pass: reclassify unknown domains with <5 occurrences
    # (already unknown, just noting the frequency)
    tier2_suspicious = []
    for skill in tier2_all:
        slug = skill["skill_slug"]
        domains = skill_domains.get(slug, [])
        has_suspicious = any(
            d["classification"] in ("suspicious", "unknown", "unparseable")
            for d in domains
        )
        if has_suspicious:
            # Add domain info to the skill for triage context
            skill_copy = {**skill, "domain_analysis": domains}
            tier2_suspicious.append(skill_copy)

    # --- Tier 3: EXEC-003, EXFIL-005/006/007 (not in Tier 1 or 2) ---
    upper_tier_slugs = tier1_slugs | tier2_slugs
    tier3_eval = []
    tier3_exfil = []

    for slug, rules in skill_rules.items():
        if slug in upper_tier_slugs:
            continue
        if "EXEC-003" in rules:
            tier3_eval.append(skills_by_slug[slug])
        exfil_rules = rules & {"EXFIL-005", "EXFIL-006", "EXFIL-007"}
        if exfil_rules:
            tier3_exfil.append(skills_by_slug[slug])

    # --- Tier 4: Noise stats ---
    tier4_count = 0
    noise_rule_counts: dict[str, int] = {}
    for slug, rules in skill_rules.items():
        if slug in upper_tier_slugs:
            continue
        if rules.issubset(NOISE_RULES):
            tier4_count += 1
            for r in rules:
                noise_rule_counts[r] = noise_rule_counts.get(r, 0) + 1

    # --- Write outputs ---
    def write_json(path: Path, data: object) -> None:
        with path.open("w") as f:
            json.dump(data, f, indent=2, default=str)

    write_json(output_dir / "tier1_c2.json", tier1_c2)
    write_json(output_dir / "tier1_revshell.json", tier1_revshell)
    write_json(output_dir / "tier1_jailbreak.json", tier1_jailbreak)
    write_json(output_dir / "tier2_curl_bash.json", tier2_all)
    write_json(output_dir / "tier2_curl_bash_suspicious.json", tier2_suspicious)
    write_json(output_dir / "tier3_eval_exec.json", tier3_eval)
    write_json(output_dir / "tier3_exfil.json", tier3_exfil)

    # Domain frequency table
    domain_table = sorted(
        [
            {"domain": d, "count": c, "classification": domain_classification.get(d, "unknown")}
            for d, c in domain_freq.items()
        ],
        key=lambda x: x["count"],
        reverse=True,
    )
    write_json(output_dir / "exec001_domains.json", domain_table)

    # Tier 4 noise stats
    write_json(output_dir / "tier4_noise_stats.json", {
        "skills_with_only_noise_rules": tier4_count,
        "noise_rule_counts": dict(sorted(
            noise_rule_counts.items(), key=lambda x: x[1], reverse=True
        )),
    })

    # Summary
    summary_lines = [
        "Triage Tier Summary",
        "=" * 40,
        "",
        f"Tier 1 — C2 IPs (NET-002):          {len(tier1_c2)} skills",
        f"Tier 1 — Reverse shells (NET-001):   {len(tier1_revshell)} skills",
        f"Tier 1 — Jailbreaks (INJECT-002):    {len(tier1_jailbreak)} skills",
        f"Tier 1 — Total unique:               {len(tier1_slugs)} skills",
        "",
        f"Tier 2 — curl|bash (EXEC-001):       {len(tier2_all)} skills (all)",
        f"Tier 2 — After domain filtering:     {len(tier2_suspicious)} skills (suspicious)",
        f"         Unique domains extracted:    {len(domain_freq)}",
        f"         Known-safe domains:          "
        f"{sum(1 for d in domain_classification.values() if d == 'known-safe')}",
        f"         Suspicious domains:          "
        f"{sum(1 for d in domain_classification.values() if d == 'suspicious')}",
        f"         Unknown domains:             "
        f"{sum(1 for d in domain_classification.values() if d == 'unknown')}",
        "",
        f"Tier 3 — eval/exec (EXEC-003):       {len(tier3_eval)} skills",
        f"Tier 3 — exfil (005/006/007):        {len(tier3_exfil)} skills",
        "",
        f"Tier 4 — Noise only:                 {tier4_count} skills (no triage needed)",
        "",
        f"Total flagged skills:                {len(skills_by_slug)}",
    ]
    summary_text = "\n".join(summary_lines) + "\n"
    (output_dir / "SUMMARY.txt").write_text(summary_text)

    print(summary_text)


if __name__ == "__main__":
    main()
