"""Network rules: detect reverse shells, C2, and tunnel patterns."""

import ipaddress
import logging
import re
from pathlib import Path
from urllib.parse import urlsplit

from waingro.analyzers.dataflow import expression_reaches_sink, statement_for_finding
from waingro.models import Finding, FindingCategory, ParsedSkill, Severity
from waingro.rules import (
    Rule,
    register_rule,
    search_skill_content,
    search_skill_content_lines,
)

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
        re.compile(r"\bnc\s+[^\n]{0,120}\s-e\s+/bin/(?:sh|bash)\b"),
        re.compile(r"\bnc\s+[^\n]{0,120}\|\s*/bin/(?:sh|bash)\b"),
        re.compile(r"\bnc\s+[^\n]{0,120}\s-c\s+['\"]?/bin/(?:sh|bash)\b"),
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

    # DNS exfiltration is a lookup tool invoked as a *command*, against a
    # hostname whose leading label is interpolated data. The previous
    # `host\s+.*\$...` pattern matched any line containing the word "host"
    # followed anywhere later by a variable and a dot, which fires on ordinary
    # prose ("host verification, host reply") and on minified JavaScript.
    #
    # Anchoring to command position is what makes this a signal: the tool must
    # start the line or follow a shell separator, and the data must sit in the
    # hostname it queries.
    _CMD_START = r"(?:^|[;&|]\s*|\$\(\s*|`\s*)"
    # Restricted to characters that can actually appear in a hostname plus
    # shell interpolation, and required to end in a TLD-shaped label. This is
    # what keeps `Write-Host "$($x.Count)"` out: `$(` is not a hostname.
    _ENCODED_LABEL = (
        r"[A-Za-z0-9._${}-]*\$\{?\w+\}?[A-Za-z0-9._${}-]*\.[A-Za-z]{2,24}\b"
    )

    _patterns = [
        re.compile(_CMD_START + r"dig\s+(?:[+-]\S+\s+)*" + _ENCODED_LABEL, re.IGNORECASE),
        re.compile(_CMD_START + r"nslookup\s+(?:-\S+\s+)*" + _ENCODED_LABEL, re.IGNORECASE),
        re.compile(_CMD_START + r"host\s+(?:-\S+\s+)*" + _ENCODED_LABEL, re.IGNORECASE),
        re.compile(
            _CMD_START
            + r"(?:dig|nslookup|host)\s+[^\n]{0,180}"
            + r"\$\([^\n)]*(?:base64|xxd|openssl|"
            + r"\$[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD))[^\n)]*\)\."
            + r"[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b",
            re.IGNORECASE,
        ),
        re.compile(r"\bdig\s+(?:[+-]\S+\s+)*\S*\.data\.", re.IGNORECASE),
        # Splitting base64 into 63-char chunks is DNS label sizing and has
        # essentially one purpose.
        re.compile(r"fold\s+-w\s*63"),
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


_PLAINTEXT_URL_RE = re.compile(r"\b(?:http|ws)://[^\s'\"`)>,]+", re.IGNORECASE)
_PLAINTEXT_HTTP_RE = re.compile(r"\bhttp://[^\s'\"`)>,]+", re.IGNORECASE)
_PLAINTEXT_WS_RE = re.compile(r"\bws://[^\s'\"`)>,]+", re.IGNORECASE)
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
_RESERVED_HOSTS = {"example.com", "example.net", "example.org"}
_PASSIVE_BUNDLED_PARTS = {
    "benchmark",
    "benchmarks",
    "fixture",
    "fixtures",
    "node_modules",
    "sample",
    "samples",
    "test",
    "tests",
}
_OUTBOUND_REQUEST_RE = re.compile(
    r"(?:"
    r"\bcurl\b|\bwget\b|\bfetch\s*\(|"
    r"\b(?:axios|requests|httpx|aiohttp)\.(?:get|post|put|patch|delete|request)\s*\(|"
    r"\b(?:http|https)\.request\s*\(|\bnew\s+WebSocket\s*\(|"
    r"\bwebsockets\.connect\s*\(|\bcreate_connection\s*\("
    r")",
    re.IGNORECASE,
)
_CREDENTIAL_TRANSMISSION_RE = re.compile(
    r"(?:"
    r"\bAuthorization\b|\bProxy-Authorization\b|"
    r"\bX[-_]?(?:API[-_]?Key|Auth[-_]?Token)\b|"
    r"\bBearer\s+(?:\$|\{)|"
    r"(?:api[-_]?key|access[-_]?token|auth[-_]?token|password)\s*[=:]\s*"
    r"(?:\$|\{|process\.env|os\.environ|os\.getenv)"
    r")",
    re.IGNORECASE,
)
_WEBSOCKET_CONNECTION_RE = re.compile(
    r"(?:"
    r"\bnew\s+(?:WebSocket|WebSocketClient)\s*\(|"
    r"\b(?:websockets|websocket)\.(?:connect|create_connection)\s*\(|"
    r"\bcreate_connection\s*\("
    r")",
    re.IGNORECASE,
)
_MACHINE_IDENTITY_PATTERNS = (
    re.compile(r"\bos\.hostname\s*\("),
    re.compile(r"\bos\.networkInterfaces\s*\("),
    re.compile(r"\bsocket\.gethostname\s*\("),
    re.compile(r"\bplatform\.node\s*\("),
    re.compile(r"\buuid\.getnode\s*\("),
    re.compile(r"\bDeno\.hostname\s*\("),
    re.compile(r"\bprocess\.env\.(?:COMPUTERNAME|HOSTNAME)\b"),
    re.compile(r"\$\(\s*hostname\b"),
    re.compile(r"\$\(\s*uname\s+(?:-[amnoprsv]+|--all)\b"),
    re.compile(r"\bos\.uname\s*\("),
    re.compile(r"\bplatform\.platform\s*\("),
)
_NETWORK_SEND_RE = re.compile(
    r"(?:"
    r"\bcurl\b|"
    r"\bfetch\s*\(|"
    r"\b(?:axios|requests|httpx|aiohttp)\.(?:post|put|patch|request)\s*\(|"
    r"\b(?:http|https)\.request\s*\(|"
    r"\b(?:send|sendall|send_json|send_str)\s*\(|"
    r"\.send\s*\("
    r")",
    re.IGNORECASE,
)


def _external_plaintext_url(text: str, *, websocket_only: bool = False) -> str | None:
    """Return the first plaintext URL whose host is not local or private."""
    pattern = _PLAINTEXT_WS_RE if websocket_only else _PLAINTEXT_URL_RE
    for match in pattern.finditer(text):
        value = match.group(0).rstrip(".;:")
        try:
            host = urlsplit(value).hostname
        except ValueError:
            # Skills frequently document placeholders such as http://[host]
            # or include prose punctuation that resembles an invalid netloc.
            # Malformed examples are not evidence about a real remote endpoint.
            continue
        if not host:
            continue
        lowered = host.lower().rstrip(".")
        if any(marker in lowered for marker in ("$", "{", "}", "<", ">")):
            continue
        if lowered == "localhost" or lowered.endswith((".localhost", ".local")):
            continue
        try:
            address = ipaddress.ip_address(lowered)
        except ValueError:
            labels = lowered.split(".")
            if (
                len(labels) < 2
                or not all(_DNS_LABEL_RE.fullmatch(label) for label in labels)
                or any(label in {"host", "hostname", "ip", "server", "x"} for label in labels)
                or lowered in _RESERVED_HOSTS
                or any(lowered.endswith(f".{reserved}") for reserved in _RESERVED_HOSTS)
            ):
                continue
            return value
        if address.is_global:
            return value
    return None


def _url_is_payload_value(source_line: str, matched: str) -> bool:
    """Return whether a URL is data inside a request rather than its destination."""
    position = source_line.find(matched)
    prefix = source_line[:position] if position >= 0 else source_line
    stripped = prefix.strip().lower()
    if re.match(r"^(?:--data(?:-raw|-binary)?|-d)\s+", stripped):
        return True
    return bool(re.search(r"[?&][a-z0-9_.-]+=$", prefix, re.IGNORECASE))


def _passive_bundled_path(path: Path) -> bool:
    return path.name != "SKILL.md" and any(
        part.lower() in _PASSIVE_BUNDLED_PARTS for part in path.parts
    )


@register_rule
class PlaintextCredentialTransport(Rule):
    rule_id = "NET-005"
    title = "Credential transmitted over plaintext transport"
    description = "Detects credentials placed in an outbound HTTP request without TLS"

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath, source_line in search_skill_content_lines(
            skill,
            [_PLAINTEXT_HTTP_RE],
        ):
            if not _external_plaintext_url(matched):
                continue
            if _passive_bundled_path(fpath) or _url_is_payload_value(source_line, matched):
                continue
            statement = statement_for_finding(skill, fpath, line)
            if not statement or not _OUTBOUND_REQUEST_RE.search(statement):
                continue
            if not _CREDENTIAL_TRANSMISSION_RE.search(statement):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=self.description,
                    severity=Severity.HIGH,
                    category=FindingCategory.NETWORK,
                    file_path=fpath,
                    line_number=line,
                    matched_content=matched[:200],
                    remediation=(
                        "Use HTTPS and reject plaintext fallback before transmitting credentials."
                    ),
                    reference="CWE-319: Cleartext Transmission of Sensitive Information",
                    context_note=(
                        "The plaintext URL and credential-bearing request occur in the same "
                        "bounded statement. This is a transport vulnerability, not proof of "
                        "malicious intent."
                    ),
                )
            )
        return findings


@register_rule
class PlaintextExternalWebSocket(Rule):
    rule_id = "NET-006"
    title = "External plaintext WebSocket channel"
    description = "Detects ws:// endpoints outside local or private networks"

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_skill_content(skill, [_PLAINTEXT_WS_RE]):
            endpoint = _external_plaintext_url(matched, websocket_only=True)
            if not endpoint:
                continue
            if _passive_bundled_path(fpath):
                continue
            if fpath.name != "SKILL.md":
                statement = statement_for_finding(skill, fpath, line)
                if not statement or not _WEBSOCKET_CONNECTION_RE.search(statement):
                    continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=self.description,
                    severity=Severity.MEDIUM,
                    category=FindingCategory.NETWORK,
                    file_path=fpath,
                    line_number=line,
                    matched_content=endpoint[:200],
                    remediation=(
                        "Use wss:// with certificate validation and authenticate both peers."
                    ),
                    reference="CWE-319: Cleartext Transmission of Sensitive Information",
                    confidence=0.9,
                    context_note=(
                        "A remote bidirectional channel is configured without transport "
                        "encryption. This is exposure evidence, not proof of command-and-control."
                    ),
                )
            )
        return findings


@register_rule
class MachineIdentityTransmission(Rule):
    rule_id = "NET-007"
    title = "Machine identity transmitted to a network sink"
    description = "Detects lexical flow from stable host identifiers into outbound data"

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_skill_content(
            skill,
            list(_MACHINE_IDENTITY_PATTERNS),
        ):
            if not expression_reaches_sink(
                skill,
                fpath,
                line,
                _MACHINE_IDENTITY_PATTERNS,
                _NETWORK_SEND_RE,
                allow_quoted_source=fpath.name == "SKILL.md",
            ):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=self.description,
                    severity=Severity.MEDIUM,
                    category=FindingCategory.NETWORK,
                    file_path=fpath,
                    line_number=line,
                    matched_content=matched[:200],
                    remediation=(
                        "Avoid stable device fingerprints; disclose, minimize, and obtain "
                        "consent for any host identity sent off-device."
                    ),
                    reference="MITRE ATT&CK T1082 (System Information Discovery)",
                    confidence=0.9,
                    context_note=(
                        "The identifier reaches a network send through direct nesting or "
                        "bounded exact-name aliases in one lexical scope. This is a privacy "
                        "signal, not proof of malicious intent."
                    ),
                )
            )
        return findings
