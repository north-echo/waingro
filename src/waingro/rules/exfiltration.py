"""Exfiltration rules: detect credential theft and data scraping patterns."""

import re

from waingro.models import Finding, FindingCategory, ParsedSkill, Severity
from waingro.rules import Rule, register_rule, search_skill_content


@register_rule
class CredentialFileAccess(Rule):
    rule_id = "EXFIL-001"
    title = "Credential file access"
    description = "Detects access to SSH keys, AWS credentials, and other sensitive files"

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
        re.compile(r"(?<!\w)\.env\b(?!\.example)"),
        re.compile(r"\bid_rsa\b"),
        re.compile(r"\bid_ed25519\b"),
        re.compile(r"\.pem\b"),
        re.compile(r"\.key\b"),
        re.compile(r"~/\.config/gh/hosts\.yml|\.config/gh/hosts\.yml"),
        re.compile(r"~/\.npmrc|\.npmrc"),
        re.compile(r"~/\.docker/config\.json|\.docker/config\.json"),
        re.compile(r"~/\.config/pip/|pip\.conf"),
        re.compile(r"Authorization:\s*Bearer", re.IGNORECASE),
        re.compile(r"oauth_token", re.IGNORECASE),
        re.compile(r"_authToken", re.IGNORECASE),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_skill_content(skill, self._patterns):
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
                    "Skills should not access SSH keys, AWS credentials, "
                    "or other sensitive files."
                ),
                reference="Bitdefender -- credential exfiltration skills scanning for key files",
            ))
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
            findings.append(Finding(
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
            ))
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
            findings.append(Finding(
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
            ))
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
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.HIGH,
                category=FindingCategory.EXFILTRATION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="Skills should not access OpenClaw memory or workspace directories.",
                reference="Bitdefender -- skills scanning OpenClaw memory/workspace dirs",
            ))
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
            findings.append(Finding(
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
            ))
        return findings


@register_rule
class EmbeddedCredentialPatterns(Rule):
    rule_id = "EXFIL-006"
    title = "Embedded credential patterns"
    description = "Detects hardcoded API keys, tokens, and cloud credentials"

    _patterns = [
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
        re.compile(r"gho_[A-Za-z0-9]{36}"),
        re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
        re.compile(r"sk-[a-zA-Z0-9]{20,}"),
        re.compile(r"xox[bpras]-[A-Za-z0-9\-]+"),
        re.compile(r"glpat-[A-Za-z0-9\-]{20,}"),
    ]

    # Placeholder patterns used in documentation/config examples
    _placeholder_re = re.compile(
        r"(?:abcdef|xxxx|0000|fake|test|example|placeholder|DO_NOT_USE"
        r"|your.?key|your.?token|REPLACE)",
        re.IGNORECASE,
    )

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_skill_content(skill, self._patterns):
            if self._placeholder_re.search(matched):
                continue
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.HIGH,
                category=FindingCategory.EXFILTRATION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="Skills must not contain hardcoded credentials or API keys.",
                reference=None,
            ))
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
            findings.append(Finding(
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
            ))
        return findings
