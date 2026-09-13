"""Exfiltration rules: detect credential theft and data scraping patterns."""

import hashlib
import re
from pathlib import Path

from waingro.analyzers.dataflow import (
    expression_reaches_sink,
    scope_for_finding,
    scope_from_finding,
    statement_for_finding,
)
from waingro.analyzers.reputation import is_first_party, skill_identifiers
from waingro.models import Finding, FindingCategory, ParsedSkill, Severity
from waingro.rules import Rule, register_rule, search_skill_content, search_skill_content_lines

# A skill touching its own workspace is doing its job. The Bitdefender pattern
# is reading that data and sending it somewhere. Without a destination in the
# same file, a path match is a description, not an exfiltration.
_EXFIL_SINK = re.compile(
    r"""(?:
        curl\s|wget\s|https?://                 # outbound fetch/post
      | requests\.(?:post|put|patch)
      | urllib\.request|httpx\.|aiohttp
      | fetch\s*\(|axios\.|XMLHttpRequest
      | nc\s+-|netcat|socket\.
      | webhook|discord\.com/api|hooks\.slack
      | \bmail\b|sendmail|smtplib
      | base64\s+(?:-w\s*0|--wrap)             # encode-then-send shape
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def _file_has_exfil_sink(skill: ParsedSkill, fpath) -> bool:
    """True if the file containing a hit also contains an outbound destination."""
    name = str(fpath)
    if fpath.name == "SKILL.md":
        haystack = skill.body
    else:
        haystack = next((bf.content for bf in skill.bundled_content if str(bf.path) == name), "")
    return bool(_EXFIL_SINK.search(haystack))


@register_rule
class CredentialFileAccess(Rule):
    rule_id = "EXFIL-001"
    title = "Sensitive credential reference"
    description = "Detects references to SSH keys, cloud credentials, and other sensitive files"

    _patterns = [
        re.compile(r"~/\.ssh/|\.ssh/id_"),
        re.compile(r"~/\.aws/credentials|\.aws/credentials"),
        re.compile(r"~/\.aws/config"),
        re.compile(r"~/\.config/gcloud/"),
        re.compile(r"~/\.kube/config|\.kube/config"),
        re.compile(r"~/\.gnupg/"),
        re.compile(r"~/\.netrc|\.netrc"),
        re.compile(r"~/\.mykey|\.mykey"),
        re.compile(r"\.env\.local\b"),
        re.compile(r"(?<!\w)\.env\b(?!\.example|\.template|\.sample)"),
        re.compile(r"\bid_rsa\b"),
        re.compile(r"\bid_ed25519\b"),
        re.compile(r"\.pem\b"),
        re.compile(r"~/\.config/gh/hosts\.yml|\.config/gh/hosts\.yml"),
        re.compile(r"~/\.npmrc|\.npmrc"),
        re.compile(r"~/\.docker/config\.json|\.docker/config\.json"),
        re.compile(r"~/\.config/pip/|pip\.conf"),
        re.compile(r"Authorization:\s*Bearer", re.IGNORECASE),
        re.compile(r"oauth_token", re.IGNORECASE),
        re.compile(r"_authToken", re.IGNORECASE),
    ]

    # Context patterns that indicate documentation, not actual access
    _doc_context_re = re.compile(
        r"example|template|sample|documentation|configure|tutorial|"
        r"\.env\.example|\.env\.template|\.env\.sample|"
        r"translation\.key|localization\.key|cache\.key|primary\.key|"
        r"README|\bconfig\b(?!/)|\bsetup\b(?!/)|CERTIFICATE|-----BEGIN|ssl_cert|tls_cert",
        re.IGNORECASE,
    )

    # API documentation context: Authorization: Bearer in curl examples / HTTP docs
    _api_doc_re = re.compile(
        r"curl\s|https?://|--header|Content-Type|application/json|"
        r"-X\s+(GET|POST|PUT|PATCH|DELETE)|fetch\(|"
        r"api\.|/api/|/v[0-9]+/|endpoint",
        re.IGNORECASE,
    )

    def _get_nearby_lines(
        self,
        skill: ParsedSkill,
        fpath: Path,
        line_num: int,
        window: int = 5,
    ) -> str:
        """Get text from +/-window lines around a match for context checking."""
        if fpath.name == "SKILL.md":
            lines = skill.body.split("\n")
        else:
            for bf in skill.bundled_content:
                if bf.path == fpath:
                    lines = bf.content.split("\n")
                    break
            else:
                return ""
        start = max(0, line_num - 1 - window)
        end = min(len(lines), line_num + window)
        return "\n".join(lines[start:end])

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line_num, fpath in search_skill_content(skill, self._patterns):
            # Get full line for context checking
            full_line = ""
            if fpath.name == "SKILL.md" and line_num:
                lines = skill.body.split("\n")
                idx = line_num - 1
                full_line = lines[idx] if 0 <= idx < len(lines) else ""
            else:
                for bf in skill.bundled_content:
                    if bf.path == fpath and line_num:
                        bf_lines = bf.content.split("\n")
                        idx = line_num - 1
                        full_line = bf_lines[idx] if 0 <= idx < len(bf_lines) else ""
                        break
            if full_line and self._doc_context_re.search(full_line):
                continue
            # Suppress Authorization: Bearer in API documentation context
            # Check current line and surrounding ±5 lines (curl commands span multiple lines)
            if "Authorization" in matched and line_num:
                context = self._get_nearby_lines(skill, fpath, line_num, window=5)
                if self._api_doc_re.search(context):
                    continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=self.description,
                    severity=Severity.MEDIUM,
                    category=FindingCategory.EXFILTRATION,
                    file_path=fpath,
                    line_number=line_num,
                    matched_content=matched[:200],
                    remediation=(
                        "Verify whether the reference performs a read. Correlate any read "
                        "with execution or egress before treating it as an attack."
                    ),
                    reference=(
                        "Bitdefender -- credential exfiltration skills scanning for key files"
                    ),
                    confidence=0.55,
                    context_note=(
                        "A path or credential marker is a capability primitive, not proof "
                        "that the skill reads or transmits a credential."
                    ),
                )
            )
        return findings


@register_rule
class KeychainAccess(Rule):
    rule_id = "EXFIL-002"
    title = "macOS Keychain access"
    description = "Detects attempts to access the macOS Keychain"

    _patterns = [
        re.compile(r"security\s+find-generic-password"),
        re.compile(r"security\s+find-internet-password"),
        re.compile(r"security\s+dump-keychain"),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_skill_content(skill, self._patterns):
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=self.description,
                    severity=Severity.CRITICAL,
                    category=FindingCategory.EXFILTRATION,
                    file_path=fpath,
                    line_number=line,
                    matched_content=matched[:200],
                    remediation="Skills must not access the macOS Keychain.",
                    reference=None,
                )
            )
        return findings


@register_rule
class BrowserCredentialAccess(Rule):
    rule_id = "EXFIL-003"
    title = "Browser credential access"
    description = "Detects access to browser credential stores"

    _patterns = [
        re.compile(r"Login Data", re.IGNORECASE),
        re.compile(r"cookies\.sqlite"),
        re.compile(r"key[34]\.db"),
        re.compile(r"logins\.json"),
        re.compile(r"Local State"),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_skill_content(skill, self._patterns):
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=self.description,
                    severity=Severity.HIGH,
                    category=FindingCategory.EXFILTRATION,
                    file_path=fpath,
                    line_number=line,
                    matched_content=matched[:200],
                    remediation="Skills should not access browser credential stores.",
                    reference=None,
                )
            )
        return findings


@register_rule
class OpenClawWorkspaceScraping(Rule):
    rule_id = "EXFIL-004"
    title = "OpenClaw workspace scraping"
    description = "Detects access to OpenClaw memory and workspace directories"

    _patterns = [
        re.compile(r"\.openclaw/memory/"),
        re.compile(r"\.openclaw/workspace/"),
        re.compile(r"clawd/memory/"),
        re.compile(r"memory\.json"),
        re.compile(r"claw_memory"),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_skill_content(skill, self._patterns):
            has_sink = _file_has_exfil_sink(skill, fpath)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=self.description,
                    severity=Severity.HIGH if has_sink else Severity.LOW,
                    category=FindingCategory.EXFILTRATION,
                    file_path=fpath,
                    line_number=line,
                    matched_content=matched[:200],
                    remediation=(
                        "Skills should not access OpenClaw memory or workspace directories."
                    ),
                    reference="Bitdefender -- skills scanning OpenClaw memory/workspace dirs",
                    confidence=0.9 if has_sink else 0.25,
                    context_note=(
                        None
                        if has_sink
                        else "Workspace path with no outbound destination in the same file. "
                        "Most skills legitimately store their own files here."
                    ),
                )
            )
        return findings


@register_rule
class EnvVariableHarvesting(Rule):
    rule_id = "EXFIL-005"
    title = "Environment variable harvesting"
    description = "Detects harvesting of secrets from environment variables"

    _patterns = [
        re.compile(r"env\s*\|\s*grep\s+.*(key|secret|token|password|api)", re.IGNORECASE),
        re.compile(r"printenv\s*\|\s*grep", re.IGNORECASE),
        re.compile(r"set\s*\|\s*grep\s+.*(key|secret|token|password)", re.IGNORECASE),
        re.compile(r"\benv\b.*grep\s+-[iIeE]+\s+.*\b(KEY|SECRET|TOKEN|PASSWORD|AWS|API)\b"),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_skill_content(skill, self._patterns):
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=self.description,
                    severity=Severity.HIGH,
                    category=FindingCategory.EXFILTRATION,
                    file_path=fpath,
                    line_number=line,
                    matched_content=matched[:200],
                    remediation="Skills should not harvest secrets from environment variables.",
                    reference=None,
                )
            )
        return findings


@register_rule
class EmbeddedCredentialPatterns(Rule):
    rule_id = "EXFIL-006"
    title = "Embedded credential patterns"
    description = "Detects hardcoded API keys, tokens, and cloud credentials"

    _named_literal_re = re.compile(
        r"\b[A-Z][A-Z0-9_]*(?:API_KEY|ACCESS_KEY|SECRET_KEY|TOKEN|PASSWORD|SECRET)\b"
        r"\s*(?:=|:)\s*[\"']?(?:\$\{[A-Z][A-Z0-9_]*:-)?"
        r"(?P<value>[A-Za-z0-9][A-Za-z0-9_./+=-]{19,})"
    )
    _patterns = [
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
        re.compile(r"gho_[A-Za-z0-9]{36}"),
        re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
        re.compile(r"sk-[a-zA-Z0-9]{20,}"),
        re.compile(r"xox[bpras]-[A-Za-z0-9\-]+"),
        re.compile(r"glpat-[A-Za-z0-9\-]{20,}"),
        _named_literal_re,
    ]

    # Placeholder patterns used in documentation/config examples
    _placeholder_re = re.compile(
        r"(?:abcdef|xxxx|0000|fake|test|example|placeholder|DO_NOT_USE"
        r"|your.?key|your.?token|REPLACE)",
        re.IGNORECASE,
    )

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        seen: set[tuple[Path, int | None]] = set()
        for matched, line, fpath in search_skill_content(skill, self._patterns):
            generic = self._named_literal_re.fullmatch(matched)
            value = generic.group("value") if generic else matched
            character_classes = sum(
                bool(pattern.search(value))
                for pattern in (
                    re.compile(r"[a-z]"),
                    re.compile(r"[A-Z]"),
                    re.compile(r"[0-9]"),
                    re.compile(r"[^A-Za-z0-9]"),
                )
            )
            if (
                self._placeholder_re.search(value)
                or (generic and (len(set(value)) < 10 or character_classes < 3))
                or (fpath, line) in seen
            ):
                continue
            seen.add((fpath, line))
            fingerprint = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=self.description,
                    severity=Severity.HIGH,
                    category=FindingCategory.EXFILTRATION,
                    file_path=fpath,
                    line_number=line,
                    matched_content=(
                        f"<redacted credential: sha256={fingerprint} length={len(value)}>"
                    ),
                    remediation="Skills must not contain hardcoded credentials or API keys.",
                    reference=None,
                    confidence=0.85,
                    context_note=(
                        "The credential value is redacted from scanner output. Hard-coding is "
                        "a secret-exposure risk, but does not independently establish "
                        "malicious intent."
                    ),
                )
            )
        return findings


@register_rule
class ClipboardMonitoring(Rule):
    rule_id = "EXFIL-007"
    title = "Clipboard monitoring"
    description = "Detects clipboard access patterns used to steal copied data"

    _patterns = [
        re.compile(r"\bpbpaste\b"),
        re.compile(r"\bpbcopy\b"),
        re.compile(r"\bxclip\s+-o\b"),
        re.compile(r"\bxclip\s+-selection\s+clipboard\b"),
        re.compile(r"\bxsel\s+--clipboard\b"),
        re.compile(r"clipboard\.get", re.IGNORECASE),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_skill_content(skill, self._patterns):
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=self.description,
                    severity=Severity.HIGH,
                    category=FindingCategory.EXFILTRATION,
                    file_path=fpath,
                    line_number=line,
                    matched_content=matched[:200],
                    remediation="Skills should not monitor or access clipboard contents.",
                    reference=None,
                )
            )
        return findings


_SENSITIVE_DATA_PATTERNS = (
    re.compile(r"(?:~|\$HOME)?/\.openclaw/agents/[^\s'\"]*/auth-profiles\.json"),
    re.compile(r"(?:~|\$HOME)?/\.openclaw/workspace/\.[\w.-]*(?:key|token|secret)\b"),
    re.compile(r"(?:~|\$HOME)?/\.ssh/(?:id_[\w.-]+|config|known_hosts)\b"),
    re.compile(r"(?:~|\$HOME)?/\.aws/(?:credentials|config)\b"),
    re.compile(r"(?:~|\$HOME)?/\.config/gcloud/(?:credentials|application_default_credentials)"),
    re.compile(r"(?:~|\$HOME)?/\.kube/config\b"),
    re.compile(r"(?:~|\$HOME)?/\.(?:npmrc|netrc)\b"),
    re.compile(r"(?:~|\$HOME)?/\.docker/config\.json\b"),
    re.compile(r"(?<![\w.-])\.env\b(?!\.(?:example|sample|template)\b)"),
    re.compile(
        r"(?:~|\$HOME)?/(?:Documents|Downloads|Desktop)/[^\s'\"]*"
        r"(?:passport|medical|psych|health|tax|wallet|seed|credential|secret|private[-_]?key)"
        r"[^\s'\"]*",
        re.IGNORECASE,
    ),
)
_ACTIVE_EGRESS_RE = re.compile(
    r"(?:"
    r"\bcurl\b[\s\S]{0,1000}?(?:--data(?:-raw|-binary)?|--form|--upload-file|-d\b|-F\b|-T\b)|"
    r"\b(?:requests|httpx|aiohttp)\.(?:post|put|patch|request)\s*\(|"
    r"\burllib\.request\.(?:Request|urlopen)\s*\(|"
    r"\bfetch\s*\(|\baxios\.(?:post|put|patch|request)\s*\(|"
    r"\b(?:send|sendall|send_json|send_str)\s*\(|\.send\s*\(|"
    r"\bgog\s+gmail\s+send\b|\bsendmail\b|\bsmtplib\b|\bmail\s+-s\b"
    r")",
    re.IGNORECASE,
)
_AGENT_EGRESS_RE = re.compile(
    r"\b(?:POST|upload|send|forward|attach|transmit)\b",
    re.IGNORECASE,
)
_LOCAL_READ_RE = re.compile(
    r"(?:\bopen\s*\(|\.read\s*\(|\bcat\s+|--data-binary\s+@|--upload-file\s+|"
    r"--attach\s+|\breadFile(?:Sync)?\s*\(|\bfs\.readFile)",
    re.IGNORECASE,
)


@register_rule
class SensitiveDataToNetwork(Rule):
    rule_id = "EXFIL-008"
    title = "Sensitive local data transmitted to an external sink"
    description = "Detects bounded flow from credential or sensitive-file paths to network sends"

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        seen: set[tuple[Path, int | None]] = set()
        for matched, line, fpath in search_skill_content(
            skill,
            list(_SENSITIVE_DATA_PATTERNS),
        ):
            direct_flow = expression_reaches_sink(
                skill,
                fpath,
                line,
                _SENSITIVE_DATA_PATTERNS,
                _ACTIVE_EGRESS_RE,
                allow_quoted_source=True,
            )
            scope = scope_for_finding(skill, fpath, line)
            ordered_scope = scope_from_finding(skill, fpath, line)
            statement = statement_for_finding(skill, fpath, line)
            instructed_flow = bool(
                fpath.name == "SKILL.md" and statement and _AGENT_EGRESS_RE.search(statement)
            )
            read = _LOCAL_READ_RE.search(ordered_scope)
            egress = _ACTIVE_EGRESS_RE.search(ordered_scope)
            source_reaches_read = expression_reaches_sink(
                skill,
                fpath,
                line,
                _SENSITIVE_DATA_PATTERNS,
                _LOCAL_READ_RE,
                allow_quoted_source=True,
            )
            scoped_flow = bool(
                fpath.name != "SKILL.md"
                and scope
                and read
                and egress
                and read.start() <= egress.start()
                and source_reaches_read
            )
            if not direct_flow and not scoped_flow and not instructed_flow:
                continue
            key = (fpath, line)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=self.description,
                    severity=Severity.HIGH,
                    category=FindingCategory.EXFILTRATION,
                    file_path=fpath,
                    line_number=line,
                    matched_content=matched[:200],
                    remediation=(
                        "Remove the transfer or require explicit disclosure, destination "
                        "validation, least-privilege access, and user confirmation."
                    ),
                    reference="MITRE ATT&CK T1041 (Exfiltration Over C2 Channel)",
                    confidence=0.95,
                    context_note=(
                        "A sensitive local path is read and reaches an active network or "
                        "messaging sink in the same statement or lexical scope. This is "
                        "behavioral evidence; intent still requires contextual review."
                    ),
                )
            )
        return findings


_ENV_NAME_PATTERN = (
    r"(?:[A-Z][A-Z0-9_]*_)?(?:API_KEY|ACCESS_KEY|SECRET_KEY|TOKEN|PASSWORD|"
    r"PASSWORDS|SECRET|CREDENTIALS|DATABASE_URL)"
)
_SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"\bdict\s*\(\s*os\.environ\s*\)"),
    re.compile(rf"\bos\.environ\s*\[\s*['\"]{_ENV_NAME_PATTERN}['\"]\s*\]"),
    re.compile(rf"\bos\.environ\.get\s*\(\s*['\"]{_ENV_NAME_PATTERN}['\"]"),
    re.compile(rf"\bos\.getenv\s*\(\s*['\"]{_ENV_NAME_PATTERN}['\"]"),
    re.compile(rf"\bprocess\.env\.{_ENV_NAME_PATTERN}\b"),
    re.compile(rf"\$(?:\{{)?{_ENV_NAME_PATTERN}(?:\}})?\b"),
)
_SECRET_NAME_RE = re.compile(_ENV_NAME_PATTERN)
_URL_HOST_RE = re.compile(r"https?://([A-Za-z0-9.-]+)", re.IGNORECASE)
_SUSPICIOUS_DESTINATION_RE = re.compile(
    r"(?:^|[.-])(?:attacker|backdoor|c2|collector|exfil|harvest|keylog|paste|"
    r"phish|relay|requestbin|sink|sniff|spoof|steal)(?:[.-]|$)",
    re.IGNORECASE,
)
_KNOWN_PROVIDER_DOMAINS = {
    "ANTHROPIC": ("anthropic.com",),
    "AWS": ("amazonaws.com", "aws.amazon.com"),
    "DOCKER": ("docker.com", "docker.io"),
    "GITHUB": ("github.com", "githubusercontent.com"),
    "GITLAB": ("gitlab.com",),
    "GOOGLE": ("google.com", "googleapis.com"),
    "NPM": ("npmjs.com", "npmjs.org"),
    "OPENAI": ("openai.com",),
    "SENDGRID": ("sendgrid.com",),
    "SLACK": ("slack.com",),
}
_GENERIC_SECRET_PREFIXES = {
    "ACCESS",
    "API",
    "AUTH",
    "DATABASE",
    "DB",
    "PASSWORD",
    "SECRET",
    "SESSION",
    "TOKEN",
}


def _secret_prefix(matched: str) -> str | None:
    match = _SECRET_NAME_RE.search(matched)
    if not match:
        return None
    name = match.group(0)
    suffixes = (
        "_API_KEY",
        "_ACCESS_KEY",
        "_SECRET_KEY",
        "_DATABASE_URL",
        "_CREDENTIALS",
        "_PASSWORDS",
        "_PASSWORD",
        "_SECRET",
        "_TOKEN",
    )
    for suffix in suffixes:
        if name.endswith(suffix):
            prefix = name[: -len(suffix)]
            provider = prefix.split("_", 1)[0]
            return provider if provider and provider not in _GENERIC_SECRET_PREFIXES else None
    return None


def _provider_is_disclosed(skill: ParsedSkill, statement: str, matched: str) -> bool:
    if is_first_party(statement, skill_identifiers(skill)):
        return True
    prefix = _secret_prefix(matched)
    if not prefix:
        return False
    token = re.sub(r"[^a-z0-9]", "", prefix.lower())
    declared = re.sub(
        r"[^a-z0-9]",
        "",
        f"{skill.metadata.name} {skill.metadata.description or ''}".lower(),
    )
    if len(token) >= 4 and token in declared:
        return True
    return any(
        token in re.sub(r"[^a-z0-9]", "", host.lower()) for host in _URL_HOST_RE.findall(statement)
    )


def _provider_mismatch_is_evident(statement: str, matched: str) -> bool:
    hosts = [host.lower().rstrip(".") for host in _URL_HOST_RE.findall(statement)]
    if any(_SUSPICIOUS_DESTINATION_RE.search(host) for host in hosts):
        return True
    prefix = _secret_prefix(matched)
    expected = _KNOWN_PROVIDER_DOMAINS.get(prefix or "")
    if not expected or not hosts:
        return False
    return not any(
        host == domain or host.endswith(f".{domain}") for host in hosts for domain in expected
    )


@register_rule
class SensitiveValueToNetwork(Rule):
    rule_id = "EXFIL-009"
    title = "Sensitive environment value transmitted externally"
    description = (
        "Detects bounded flow from the process environment or secret-named values "
        "to an outbound data sink"
    )

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        seen: set[tuple[Path, int | None]] = set()
        for matched, line, fpath in search_skill_content(
            skill,
            list(_SENSITIVE_VALUE_PATTERNS),
        ):
            if not expression_reaches_sink(
                skill,
                fpath,
                line,
                _SENSITIVE_VALUE_PATTERNS,
                _ACTIVE_EGRESS_RE,
                allow_quoted_source=fpath.name == "SKILL.md",
            ):
                continue
            statement = statement_for_finding(skill, fpath, line)
            scope = scope_for_finding(skill, fpath, line)
            disclosed = _provider_is_disclosed(skill, statement or scope, matched)
            reads_all = bool(re.search(r"\bdict\s*\(\s*os\.environ", matched))
            mismatch = _provider_mismatch_is_evident(statement or scope, matched)
            ambiguous = not disclosed and not reads_all and not mismatch
            key = (fpath, line)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=self.description,
                    severity=Severity.MEDIUM if disclosed or ambiguous else Severity.HIGH,
                    category=FindingCategory.EXFILTRATION,
                    file_path=fpath,
                    line_number=line,
                    matched_content=matched[:200],
                    remediation=(
                        "Transmit only the named value required by a verified destination. "
                        "Never upload the complete process environment."
                    ),
                    reference="MITRE ATT&CK T1552.001 and T1041",
                    confidence=0.7 if disclosed or ambiguous else 0.95,
                    context_note=(
                        "The value reaches an outbound data sink in one lexical scope. "
                        + (
                            "The provider or first-party destination is disclosed, so this "
                            "is a credential-handling warning rather than intent evidence."
                            if disclosed
                            else (
                                "The variable name is generic, so provider mismatch cannot "
                                "be established; treat this as a handling warning."
                                if ambiguous
                                else "The destination is not tied to the credential provider "
                                "or declared skill identity; review as possible exfiltration."
                            )
                        )
                    ),
                )
            )
        return findings


@register_rule
class BulkSensitiveEnvironmentAccess(Rule):
    rule_id = "EXFIL-010"
    title = "Bulk sensitive environment access"
    description = (
        "Detects access to the complete process environment or multiple distinct "
        "secret-named environment values in one lexical scope"
    )

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        grouped: dict[tuple[Path, str], list[tuple[str, int | None]]] = {}
        for matched, line, fpath, _source_line in search_skill_content_lines(
            skill,
            list(_SENSITIVE_VALUE_PATTERNS),
        ):
            scope = scope_for_finding(skill, fpath, line)
            if not scope:
                continue
            grouped.setdefault((fpath, scope), []).append((matched, line))

        findings = []
        for (fpath, _scope), hits in grouped.items():
            reads_all = any(re.search(r"\bdict\s*\(\s*os\.environ", hit) for hit, _ in hits)
            names = {
                match.group(0) for hit, _line in hits if (match := _SECRET_NAME_RE.search(hit))
            }
            if not reads_all and len(names) < 2:
                continue
            first_match, first_line = hits[0]
            evidence = "complete process environment" if reads_all else ", ".join(sorted(names))
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=self.description,
                    severity=Severity.HIGH if reads_all else Severity.MEDIUM,
                    category=FindingCategory.EXFILTRATION,
                    file_path=fpath,
                    line_number=first_line,
                    matched_content=evidence or first_match[:200],
                    remediation=(
                        "Read only the single credential required for the declared action. "
                        "Do not enumerate the whole process environment."
                    ),
                    reference="MITRE ATT&CK T1552.001: Credentials In Files",
                    confidence=0.9 if reads_all else 0.75,
                    context_note=(
                        "Bulk secret access is a collection signal even when no outbound "
                        "sink is visible in the same scope. It does not establish intent."
                    ),
                )
            )
        return findings
