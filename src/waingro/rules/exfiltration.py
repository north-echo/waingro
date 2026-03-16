"""Exfiltration rules: detect credential theft and data scraping patterns."""

import re
from pathlib import Path

from waingro.models import Finding, FindingCategory, ParsedSkill, Severity
from waingro.rules import Rule, register_rule


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
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in _search_body_and_blocks(skill, self._patterns):
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
        for matched, line, fpath in _search_body_and_blocks(skill, self._patterns):
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
        for matched, line, fpath in _search_body_and_blocks(skill, self._patterns):
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
        for matched, line, fpath in _search_body_and_blocks(skill, self._patterns):
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
