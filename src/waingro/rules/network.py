"""Network rules: detect reverse shells, C2, and tunnel patterns."""

import re
from pathlib import Path

from waingro.models import Finding, FindingCategory, ParsedSkill, Severity
from waingro.rules import Rule, register_rule

KNOWN_C2_IPS = [
    "91.92.242.30",
]


def _search_body_and_blocks(
    skill: ParsedSkill, patterns: list[re.Pattern],
) -> list[tuple[str, int | None, Path]]:
    hits = []
    body_lines = skill.body.split("\n")
    skill_md = skill.path / "SKILL.md"

    for i, line in enumerate(body_lines, start=1):
        for pat in patterns:
            m = pat.search(line)
            if m:
                hits.append((m.group(0), i, skill_md))

    for block in skill.code_blocks:
        for j, line in enumerate(block["content"].split("\n")):
            for pat in patterns:
                m = pat.search(line)
                if m:
                    hits.append((m.group(0), block["line"] + j, skill_md))

    return hits


@register_rule
class ReverseShell(Rule):
    rule_id = "NET-001"
    title = "Reverse shell pattern"
    description = "Detects common reverse shell patterns"

    _patterns = [
        re.compile(r"bash\s+-i\s+>&\s*/dev/tcp/"),
        re.compile(r"import\s+socket\s*,\s*subprocess\s*,\s*os"),
        re.compile(r"nc\s+(-e|--exec)\s+/bin/(sh|bash)"),
        re.compile(r"fsockopen\s*\("),
        re.compile(r"ruby\s+-rsocket"),
        re.compile(r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+"),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in _search_body_and_blocks(skill, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.CRITICAL,
                category=FindingCategory.NETWORK,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="Skills must not contain reverse shell patterns.",
                reference="AuthTool campaign -- dormant reverse shells",
            ))
        return findings


@register_rule
class KnownC2Infrastructure(Rule):
    rule_id = "NET-002"
    title = "Known malicious infrastructure"
    description = "Detects references to known command-and-control IP addresses"

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        patterns = [re.compile(re.escape(ip)) for ip in KNOWN_C2_IPS]
        findings = []
        for matched, line, fpath in _search_body_and_blocks(skill, patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.CRITICAL,
                category=FindingCategory.NETWORK,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="This IP address is associated with known malicious infrastructure.",
                reference="Bitdefender -- recurring C2 IP from ClawHavoc",
            ))
        return findings


@register_rule
class TunnelProxy(Rule):
    rule_id = "NET-003"
    title = "Tunnel/proxy setup"
    description = "Detects use of tunneling or proxy services"

    _patterns = [
        re.compile(r"\bngrok\b"),
        re.compile(r"\bcloudflared\b"),
        re.compile(r"bore\.pub"),
        re.compile(r"\blocaltunnel\b"),
        re.compile(r"serveo\.net"),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in _search_body_and_blocks(skill, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.HIGH,
                category=FindingCategory.NETWORK,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="Skills should not set up network tunnels or proxies.",
                reference=None,
            ))
        return findings
