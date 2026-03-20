"""Network rules: detect reverse shells, C2, and tunnel patterns."""

import logging
import re
from pathlib import Path

from waingro.models import Finding, FindingCategory, ParsedSkill, Severity
from waingro.rules import Rule, register_rule, search_skill_content

logger = logging.getLogger(__name__)

_BLOCKLIST_PATH = Path(__file__).parent.parent / "data" / "c2_blocklist.txt"

# Fallback if blocklist file is missing
_FALLBACK_C2_IPS = ["91.92.242.30"]


def _load_blocklist() -> list[dict]:
    """Load C2 blocklist from data file. Returns list of {ip, campaign, source}."""
    if not _BLOCKLIST_PATH.exists():
        logger.warning("C2 blocklist not found at %s, using fallback", _BLOCKLIST_PATH)
        return [{"ip": ip, "campaign": "unknown", "source": "hardcoded fallback"}
                for ip in _FALLBACK_C2_IPS]
    entries = []
    for line in _BLOCKLIST_PATH.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) >= 1:
            entries.append({
                "ip": parts[0].strip(),
                "campaign": parts[1].strip() if len(parts) > 1 else "unknown",
                "source": parts[3].strip() if len(parts) > 3 else "",
            })
    return entries


C2_BLOCKLIST = _load_blocklist()
KNOWN_C2_IPS = [e["ip"] for e in C2_BLOCKLIST]
_IP_TO_CAMPAIGN = {e["ip"]: e["campaign"] for e in C2_BLOCKLIST}


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
        for matched, line, fpath in search_skill_content(skill, patterns):
            campaign = _IP_TO_CAMPAIGN.get(matched.strip(), "unknown")
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
                reference=f"Campaign: {campaign}",
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
