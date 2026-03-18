"""Network rules: detect reverse shells, C2, and tunnel patterns."""

import re

from waingro.models import Finding, FindingCategory, ParsedSkill, Severity
from waingro.rules import Rule, register_rule, search_skill_content

KNOWN_C2_IPS = [
    "91.92.242.30",
]


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
        for matched, line, fpath in search_skill_content(skill,self._patterns):
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
        for matched, line, fpath in search_skill_content(skill,patterns):
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
        for matched, line, fpath in search_skill_content(skill,self._patterns):
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


@register_rule
class DnsExfiltration(Rule):
    rule_id = "NET-004"
    title = "DNS data exfiltration"
    description = "Detects DNS queries used as a covert data exfiltration channel"

    _patterns = [
        re.compile(r"dig\s+.*\$\{?\w+\}?\..*\.", re.IGNORECASE),
        re.compile(r"nslookup\s+.*\$\{?\w+\}?\."),
        re.compile(r"dig\s+.*\.data\.", re.IGNORECASE),
        re.compile(r"host\s+.*\$\{?\w+\}?\.", re.IGNORECASE),
        re.compile(r"fold\s+-w\s+63"),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_skill_content(skill, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.CRITICAL,
                category=FindingCategory.NETWORK,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="Skills should not encode data into DNS queries.",
                reference=None,
            ))
        return findings
