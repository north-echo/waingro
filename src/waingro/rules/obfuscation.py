"""Obfuscation rules: detect encoding and string tricks to hide malicious intent."""

import re

from waingro.models import Finding, FindingCategory, ParsedSkill, Severity
from waingro.rules import Rule, register_rule, search_skill_content

# Patterns that look like base64 but are actually common non-malicious content
_BASE64_EXCLUSIONS = [
    re.compile(r"^[0-9a-fA-F]+$"),                          # Pure hex (SHA, commit hashes)
    re.compile(r"^0x[0-9a-fA-F]+$"),                         # Ethereum/blockchain addresses
    re.compile(r"^So[1-9A-HJ-NP-Za-km-z]{32,44}$"),         # Solana addresses
    re.compile(r"^[a-z0-9/]+$"),                             # Lowercase path segments (URLs)
    re.compile(r"com/\w+/\w+/commit/"),                      # Git commit URLs
    re.compile(r"^[A-Za-z0-9]{8}(-[A-Za-z0-9]{4}){3}-[A-Za-z0-9]{12}$"),  # UUIDs
    re.compile(r"packages/|components/|src/|lib/|dist/"),     # Import/file paths
]


def _is_excluded_base64(matched: str) -> bool:
    """Return True if the matched string is a known non-malicious pattern."""
    return any(pat.search(matched) for pat in _BASE64_EXCLUSIONS)


@register_rule
class Base64Strings(Rule):
    rule_id = "OBFUSC-001"
    title = "Base64 encoded strings in instructions"
    description = "Detects long base64-encoded strings that may hide malicious content"

    _patterns = [
        re.compile(r"[A-Za-z0-9+/]{80,}={0,2}"),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_skill_content(skill, self._patterns):
            if _is_excluded_base64(matched):
                continue
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.MEDIUM,
                category=FindingCategory.OBFUSCATION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:80] + "..." if len(matched) > 80 else matched,
                remediation="Decode and inspect base64 strings before trusting skill content.",
                reference=None,
            ))
        return findings


@register_rule
class StringConcatenation(Rule):
    rule_id = "OBFUSC-002"
    title = "String concatenation to hide commands"
    description = "Detects variable concatenation patterns used to evade detection"

    _patterns = [
        re.compile(r'\$\{[A-Z_]+\}\$\{[A-Z_]+\}'),
        re.compile(r'\$[a-zA-Z_]+\$[a-zA-Z_]+\$[a-zA-Z_]+'),
        re.compile(r"['\"][a-z]{1,4}['\"]\s*\+\s*['\"][a-z]{1,4}['\"]\s*\+\s*['\"]"),
        re.compile(r"chr\(\d+\)\s*\+\s*chr\(\d+\)"),
        re.compile(r'\$\(\s*echo\s+\w+\s*\)'),
        re.compile(r"__import__\s*\(\s*['\"].*['\"]\s*\.\s*join"),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_skill_content(skill, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.MEDIUM,
                category=FindingCategory.OBFUSCATION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="Review concatenated strings for hidden commands.",
                reference=None,
            ))
        return findings
