"""MCP-005 and MCP-006: Credential access and sensitive file access."""

import re

from waingro.mcp.models import Finding, FindingCategory, ParsedMCPServer, Severity
from waingro.rules.mcp import MCPRule, register_rule, search_source_content


@register_rule
class CredentialAccess(MCPRule):
    rule_id = "MCP-005"
    title = "Credential file/variable access"
    description = (
        "Detects MCP tool handler code that reads credential files, environment "
        "variables containing secrets, or accesses keychain/credential stores"
    )

    _file_patterns = [
        # SSH keys
        re.compile(r"~/\.ssh/|\.ssh/id_|\.ssh/authorized_keys"),
        re.compile(r"\bid_rsa\b|\bid_ed25519\b|\bid_ecdsa\b"),

        # Cloud credentials
        re.compile(r"~/\.aws/credentials|\.aws/credentials"),
        re.compile(r"~/\.config/gcloud/|application_default_credentials\.json"),
        re.compile(r"~/\.kube/config|\.kube/config"),
        re.compile(r"~/\.azure/|\.azure/accessTokens\.json"),

        # Package manager tokens
        re.compile(r"~/\.npmrc|\.npmrc"),
        re.compile(r"~/\.docker/config\.json|\.docker/config\.json"),
        re.compile(r"~/\.config/gh/hosts\.yml"),
        re.compile(r"~/\.pypirc|\.pypirc"),

        # Generic credential files
        re.compile(r"~/\.netrc|\.netrc"),
        re.compile(r"~/\.gnupg/"),
        re.compile(r"\.pem\b"),
        # .env requires read/open context to avoid FP on filesystem tools listing files
        re.compile(r"(?:readFile|readFileSync|open|read_text|load_dotenv)\s*\([^)]*\.env\b(?!\.example|\.template|\.sample)"),
        re.compile(r"(?:readFile|readFileSync|open|read_text|load_dotenv)\s*\([^)]*\.env\.local\b"),
    ]

    _env_harvest_patterns = [
        # Bulk env harvesting — only match patterns that dump ALL env vars
        re.compile(r"Object\.keys\s*\(\s*process\.env\s*\)"),
        re.compile(r"Object\.entries\s*\(\s*process\.env\s*\)"),
        re.compile(r"JSON\.stringify\s*\(\s*process\.env\s*\)"),
        re.compile(r"dict\s*\(\s*os\.environ\s*\)"),
        re.compile(r"os\.environ\.copy\s*\(\s*\)"),
        re.compile(r"env\s*\|\s*grep\s+.*(key|secret|token|password|api)", re.IGNORECASE),
        re.compile(r"printenv\s*\|\s*grep", re.IGNORECASE),
    ]

    _keychain_patterns = [
        re.compile(r"security\s+find-generic-password"),
        re.compile(r"security\s+find-internet-password"),
        re.compile(r"security\s+dump-keychain"),
    ]

    _embedded_cred_patterns = [
        # Known credential formats
        re.compile(r"AKIA[0-9A-Z]{16}"),          # AWS access key
        re.compile(r"ghp_[A-Za-z0-9]{36}"),        # GitHub PAT
        re.compile(r"gho_[A-Za-z0-9]{36}"),        # GitHub OAuth
        re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
        re.compile(r"sk-[a-zA-Z0-9]{20,}"),        # OpenAI / Stripe
        re.compile(r"xox[bpras]-[A-Za-z0-9\-]+"),  # Slack tokens
        re.compile(r"glpat-[A-Za-z0-9\-]{20,}"),   # GitLab PAT
    ]

    _placeholder_re = re.compile(
        r"(?:abcdef|xxxx|0000|fake|test|example|placeholder|DO_NOT_USE|your.?key|REPLACE)",
        re.IGNORECASE,
    )

    _doc_context_re = re.compile(
        r"example|template|sample|documentation|configure|tutorial|README",
        re.IGNORECASE,
    )

    def evaluate(self, server: ParsedMCPServer) -> list[Finding]:
        findings = []

        all_patterns = self._file_patterns + self._env_harvest_patterns + self._keychain_patterns
        for matched, line, fpath in search_source_content(server, all_patterns):
            # Skip documentation context
            full_line = self._get_line(server, fpath, line)
            if full_line and self._doc_context_re.search(full_line):
                continue

            sev = Severity.CRITICAL if any(p.search(matched) for p in self._keychain_patterns) else Severity.HIGH
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=sev,
                category=FindingCategory.EXFILTRATION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation=(
                    "MCP servers should not access credential files, harvest "
                    "environment variables, or read keychain entries."
                ),
                reference="Bitdefender -- credential exfiltration in agent tools",
            ))

        # Embedded credentials
        for matched, line, fpath in search_source_content(server, self._embedded_cred_patterns):
            if self._placeholder_re.search(matched):
                continue
            findings.append(Finding(
                rule_id=self.rule_id,
                title="Embedded credential pattern",
                description="Hardcoded API key or token found in MCP server code",
                severity=Severity.HIGH,
                category=FindingCategory.EXFILTRATION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="Do not hardcode credentials. Use environment variables or secret management.",
                reference=None,
            ))

        return findings

    def _get_line(self, server: ParsedMCPServer, fpath, line_num: int) -> str:
        content = server.source_content.get(fpath, "")
        lines = content.split("\n")
        idx = line_num - 1
        return lines[idx] if 0 <= idx < len(lines) else ""


@register_rule
class SensitiveFileAccess(MCPRule):
    rule_id = "MCP-006"
    title = "Sensitive file access"
    description = (
        "Detects MCP tool handlers that access browser credential stores, "
        "chat histories, password databases, or other sensitive user data"
    )

    _patterns = [
        # Browser credential stores
        re.compile(r"Login Data", re.IGNORECASE),
        re.compile(r"cookies\.sqlite"),
        re.compile(r"key[34]\.db"),
        re.compile(r"logins\.json"),
        re.compile(r"Local State"),

        # Password managers
        re.compile(r"\.kdbx\b"),          # KeePass
        re.compile(r"1password|\.opvault", re.IGNORECASE),
        re.compile(r"\.bitwarden\b", re.IGNORECASE),

        # Chat/messaging data
        re.compile(r"\.config/Signal/"),
        re.compile(r"\.config/discord/"),
        re.compile(r"Library/Messages/chat\.db"),
        re.compile(r"telegram\.session"),

        # Clipboard monitoring
        re.compile(r"\bpbpaste\b"),
        re.compile(r"\bpbcopy\b"),
        re.compile(r"\bxclip\s+-o\b"),
        re.compile(r"clipboard\.get", re.IGNORECASE),

        # Broad filesystem enumeration
        re.compile(r"os\.walk\s*\(\s*['\"](?:/|~|\\\\)"),
        re.compile(r"glob\.glob\s*\(\s*['\"](?:/|\*\*/\*)"),
        re.compile(r"readdirSync\s*\(\s*['\"](?:/|~)"),
    ]

    def evaluate(self, server: ParsedMCPServer) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_source_content(server, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.HIGH,
                category=FindingCategory.EXFILTRATION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation=(
                    "MCP servers should not access browser credentials, "
                    "password databases, chat histories, or enumerate the filesystem."
                ),
                reference=None,
            ))
        return findings
