#!/usr/bin/env python3
"""Automated triage for WAINGRO audit findings.

Reads tier files and skill content, applies analyst heuristics to produce
verdicts. Outputs triage_results.json compatible with triage.py --summary.

Usage:
    python scripts/auto_triage.py \
        --tiers-dir ~/clawhub-corpus/audit_results_v2/triage_tiers/ \
        --corpus ~/clawhub-corpus/skills/ \
        --output ~/clawhub-corpus/audit_results_v2/triage_results.json
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

# --- Heuristics ---

# C2 IP from Bitdefender ClawHavoc report
KNOWN_C2_IP = "91.92.242.30"

# Domains that are definitely malicious in a curl|bash context
MALICIOUS_DOMAINS = {
    "evil.com", "evil.site", "evil.example.com", "malicious.site",
    "malicious.example", "random.site",
}

# Domains that are definitely safe in a curl|bash context
SAFE_DOMAINS = {
    "raw.githubusercontent.com", "github.com", "objects.githubusercontent.com",
    "astral.sh", "bun.sh", "sh.rustup.rs", "rustup.rs",
    "deb.nodesource.com", "get.docker.com", "brew.sh",
    "mise.jdx.dev", "mise.run", "cli.github.com", "deno.land",
    "get.helm.sh", "starship.rs", "ohmyz.sh", "install.python-poetry.org",
    "pypi.org", "download.docker.com", "rpm.nodesource.com",
    "get.sdkman.io", "sdkman.io", "ollama.com", "ollama.ai",
    "tailscale.com", "fly.io", "download.newrelic.com", "get.tur.so",
    "foundry.paradigm.xyz",
}

# Patterns in SKILL.md body that indicate educational/documentation context
EDUCATIONAL_PATTERNS = re.compile(
    r"example|demonstration|sample|tutorial|educational|for\s+testing|"
    r"do\s+not\s+run|placeholder|dummy|template",
    re.IGNORECASE,
)

# Patterns that indicate real malicious intent
MALICIOUS_INTENT_PATTERNS = re.compile(
    r"exfiltrat|steal|harvest|keylog|backdoor|trojan|"
    r"c2\.test|beacon|reverse.shell|bind.shell",
    re.IGNORECASE,
)

URL_RE = re.compile(r"https?://([^\s/\"'|>]+)")
IP_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")


def read_skill_content(corpus: Path, skill: dict) -> str | None:
    """Read SKILL.md content for a skill."""
    skill_path = Path(skill.get("skill_path", ""))
    skill_md = skill_path / "SKILL.md"
    if skill_md.exists():
        return skill_md.read_text(encoding="utf-8", errors="replace")

    # Search by slug
    slug = skill["skill_slug"]
    for candidate in corpus.rglob("SKILL.md"):
        if candidate.parent.name == slug:
            return candidate.read_text(encoding="utf-8", errors="replace")
    return None


def read_bundled_content(corpus: Path, skill: dict) -> dict[str, str]:
    """Read all bundled files for a skill."""
    skill_path = Path(skill.get("skill_path", ""))
    if not skill_path.is_dir():
        return {}
    bundled = {}
    for ext in (".sh", ".py", ".js", ".json"):
        for f in skill_path.rglob(f"*{ext}"):
            if f.name != "SKILL.md":
                content = f.read_text(encoding="utf-8", errors="replace")
                bundled[str(f.relative_to(skill_path))] = content
    return bundled


def extract_domains_from_findings(skill: dict) -> set[str]:
    """Extract all domains from a skill's findings."""
    domains = set()
    for f in skill.get("findings", []):
        matched = f.get("matched_content", "")
        for m in URL_RE.finditer(matched):
            domains.add(m.group(1).split("/")[0].split(":")[0])
    return domains


def triage_tier1_c2(skill: dict, content: str | None, bundled: dict) -> tuple[str, str]:
    """Triage a Tier 1 C2 skill."""
    all_text = (content or "") + " ".join(bundled.values())

    # If it references the known ClawHavoc C2 IP, it's TP
    if KNOWN_C2_IP in all_text:
        return "TP", f"References known ClawHavoc C2 IP {KNOWN_C2_IP}"

    # Any other C2 IP reference
    c2_findings = [f for f in skill["findings"] if f["rule_id"] == "NET-002"]
    if c2_findings:
        ip = c2_findings[0]["matched_content"][:20]
        return "TP", f"References known C2 infrastructure: {ip}"

    return "SUS", "NET-002 finding but could not confirm C2 IP in content"


def triage_tier1_revshell(skill: dict, content: str | None, bundled: dict) -> tuple[str, str]:
    """Triage a Tier 1 reverse shell skill."""
    all_text = (content or "") + " ".join(bundled.values())

    # Check for educational/documentation context
    if EDUCATIONAL_PATTERNS.search(all_text):
        # Even in educational context, a full reverse shell payload is SUS
        return "SUS", "Reverse shell pattern in possibly educational context"

    # Real reverse shell patterns are almost always TP
    revshell_findings = [f for f in skill["findings"] if f["rule_id"] == "NET-001"]
    matched = revshell_findings[0]["matched_content"] if revshell_findings else ""
    return "TP", f"Reverse shell pattern: {matched[:80]}"


def triage_tier1_jailbreak(skill: dict, content: str | None, bundled: dict) -> tuple[str, str]:
    """Triage a Tier 1 jailbreak skill."""
    jb_findings = [f for f in skill["findings"] if f["rule_id"] == "INJECT-002"]
    matched = jb_findings[0]["matched_content"] if jb_findings else ""

    # Check if the skill is about security/testing jailbreaks
    name = skill.get("skill_slug", "").lower()
    if any(w in name for w in ("guard", "detect", "filter", "safe", "moderate")):
        return "SUS", f"Jailbreak pattern in security-related skill: {matched[:60]}"

    return "TP", f"Jailbreak/DAN pattern: {matched[:80]}"


def triage_tier2_curl_bash(skill: dict, content: str | None, bundled: dict) -> tuple[str, str]:
    """Triage a Tier 2 curl|bash skill."""
    domains = extract_domains_from_findings(skill)

    # Check for known malicious domains
    mal_domains = domains & MALICIOUS_DOMAINS
    if mal_domains:
        return "TP", f"curl|bash with malicious domain: {', '.join(mal_domains)}"

    # Check for bare IP addresses
    ip_domains = {d for d in domains if IP_RE.fullmatch(d)}
    if ip_domains:
        return "SUS", f"curl|bash with IP address: {', '.join(ip_domains)}"

    # Check for known safe domains only
    if domains and domains.issubset(SAFE_DOMAINS):
        return "FP", f"curl|bash with known-safe domain(s): {', '.join(domains)}"

    # Check for HTTP (not HTTPS)
    exec001 = [f for f in skill["findings"] if f["rule_id"] == "EXEC-001"]
    http_urls = [f for f in exec001 if "http://" in f.get("matched_content", "")]
    if http_urls:
        matched = http_urls[0]["matched_content"][:80]
        # Check if it also has exfil or persistence findings
        other_rules = {f["rule_id"] for f in skill["findings"]} - {"EXEC-001", "OBFUSC-001"}
        if other_rules & {"EXFIL-001", "EXFIL-005", "NET-001", "NET-002", "PERSIST-001"}:
            return "TP", f"curl|bash over HTTP with additional suspicious findings: {matched}"
        return "SUS", f"curl|bash over HTTP: {matched}"

    # Unknown domains
    unknown = domains - SAFE_DOMAINS - MALICIOUS_DOMAINS
    if unknown:
        return "SUS", f"curl|bash with unknown domain(s): {', '.join(list(unknown)[:3])}"

    return "SUS", "curl|bash — could not determine domain safety"


def triage_tier3_eval(skill: dict, content: str | None, bundled: dict) -> tuple[str, str]:
    """Triage a Tier 3 eval/exec skill."""
    all_text = (content or "") + " ".join(bundled.values())
    other_rules = {f["rule_id"] for f in skill["findings"]}

    # If eval is combined with network/exfil rules, more suspicious
    if other_rules & {"NET-001", "NET-002", "EXEC-001", "EXFIL-005"}:
        return "SUS", "eval/exec combined with network/exfiltration findings"

    # Check for remote content being eval'd
    if re.search(r"eval.*\$\(curl|eval.*fetch|eval.*request", all_text, re.IGNORECASE):
        return "SUS", "eval of remote content"

    # Most eval/exec in skill files is legitimate (subprocess, os.system for tooling)
    eval_findings = [f for f in skill["findings"] if f["rule_id"] == "EXEC-003"]
    matched = eval_findings[0]["matched_content"] if eval_findings else ""

    # subprocess.run(..., shell=True) is very common in legitimate skills
    if "subprocess" in matched and "shell=True" in matched:
        return "FP", f"subprocess with shell=True (common pattern): {matched[:60]}"
    if "os.system" in matched:
        return "FP", f"os.system call (common pattern): {matched[:60]}"

    return "SUS", f"eval/exec pattern: {matched[:80]}"


def triage_tier3_exfil(skill: dict, content: str | None, bundled: dict) -> tuple[str, str]:
    """Triage a Tier 3 exfil skill."""
    rules = {f["rule_id"] for f in skill["findings"]}

    # EXFIL-006 (embedded credentials) is usually TP
    if "EXFIL-006" in rules:
        cred_findings = [f for f in skill["findings"] if f["rule_id"] == "EXFIL-006"]
        matched = cred_findings[0]["matched_content"] if cred_findings else ""
        # Check if it's in an example/documentation context
        if "example" in matched.lower() or "fake" in matched.lower() or "test" in matched.lower():
            return "FP", f"Embedded credential in example context: {matched[:60]}"
        return "SUS", f"Embedded credential pattern: {matched[:60]}"

    # EXFIL-007 (clipboard) combined with network exfil
    if "EXFIL-007" in rules:
        if rules & {"EXEC-001", "NET-001", "NET-002"}:
            return "SUS", "Clipboard access combined with network exfiltration"
        return "FP", "Clipboard access without exfiltration channel (likely productivity tool)"

    # EXFIL-005 (env harvesting)
    if "EXFIL-005" in rules:
        return "SUS", "Environment variable harvesting pattern"

    return "SUS", "Exfiltration pattern detected"


def run_auto_triage(tiers_dir: Path, corpus: Path, output_path: Path) -> None:
    """Run automated triage across all tiers."""
    results = []
    if output_path.exists():
        with output_path.open() as f:
            results = json.load(f)
    done_keys = {f"{r['skill_slug']}:{r.get('skill_version', '')}" for r in results}

    tier_handlers = [
        ("tier1_c2.json", triage_tier1_c2),
        ("tier1_revshell.json", triage_tier1_revshell),
        ("tier1_jailbreak.json", triage_tier1_jailbreak),
        ("tier2_curl_bash_suspicious.json", triage_tier2_curl_bash),
        ("tier3_eval_exec.json", triage_tier3_eval),
        ("tier3_exfil.json", triage_tier3_exfil),
    ]

    for tier_file, handler in tier_handlers:
        tier_path = tiers_dir / tier_file
        if not tier_path.exists():
            print(f"  Skipping {tier_file} (not found)")
            continue

        with tier_path.open() as f:
            skills = json.load(f)

        # For Tier 3, sample 100
        if tier_file.startswith("tier3_") and len(skills) > 100:
            import random
            random.seed(42)  # noqa: S311
            skills = random.sample(skills, 100)

        tier_results = {"TP": 0, "FP": 0, "SUS": 0}
        new_this_tier = 0

        for skill in skills:
            key = f"{skill['skill_slug']}:{skill.get('skill_version', '')}"
            if key in done_keys:
                continue

            content = read_skill_content(corpus, skill)
            bundled = read_bundled_content(corpus, skill)
            verdict, notes = handler(skill, content, bundled)

            tier_results[verdict] = tier_results.get(verdict, 0) + 1
            new_this_tier += 1

            results.append({
                "skill_slug": skill["skill_slug"],
                "skill_version": skill.get("skill_version", "unknown"),
                "skill_path": skill.get("skill_path", ""),
                "verdict": verdict,
                "analyst_notes": notes,
                "finding_count": skill.get("finding_count", 0),
                "findings": [
                    {
                        "rule_id": f.get("rule_id"),
                        "severity": f.get("severity"),
                        "matched_content": f.get("matched_content", "")[:200],
                    }
                    for f in skill.get("findings", [])[:20]  # cap at 20 findings per skill
                ],
                "tier_source": tier_file,
                "triaged_at": datetime.now(tz=UTC).isoformat(),
                "auto_triaged": True,
            })
            done_keys.add(key)

        tp = tier_results.get("TP", 0)
        fp = tier_results.get("FP", 0)
        sus = tier_results.get("SUS", 0)
        print(f"  {tier_file}: {new_this_tier} triaged — {tp} TP, {fp} FP, {sus} SUS")

    # Save
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w") as f:
        json.dump(results, f, indent=2, default=str)

    # Print summary
    total = len(results)
    tp_all = sum(1 for r in results if r["verdict"] == "TP")
    fp_all = sum(1 for r in results if r["verdict"] == "FP")
    sus_all = sum(1 for r in results if r["verdict"] == "SUS")

    print(f"\nTotal triaged: {total}")
    print(f"  TP:  {tp_all}")
    print(f"  FP:  {fp_all}")
    print(f"  SUS: {sus_all}")

    if tp_all:
        print(f"\nTrue Positives ({tp_all}):")
        tps = [r for r in results if r["verdict"] == "TP"]
        for r in tps:
            print(f"  - {r['skill_slug']}: {r['analyst_notes']}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Automated triage for WAINGRO audit")
    parser.add_argument("--tiers-dir", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    print("Running automated triage...")
    run_auto_triage(
        args.tiers_dir.expanduser().resolve(),
        args.corpus.expanduser().resolve(),
        args.output.expanduser().resolve(),
    )
