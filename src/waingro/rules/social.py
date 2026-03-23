"""Social engineering rules: detect fake dependencies and misleading error messages."""

import logging
import re
from pathlib import Path

from waingro.models import Finding, FindingCategory, ParsedSkill, Severity
from waingro.rules import Rule, register_rule, search_skill_content

logger = logging.getLogger(__name__)

_PACKAGES_PATH = Path(__file__).parent.parent / "data" / "known_packages.txt"

_FALLBACK_PACKAGES = {
    "click", "rich", "pyyaml", "requests", "flask", "django", "fastapi",
    "numpy", "pandas", "scipy", "matplotlib", "pytest", "setuptools",
    "pip", "wheel", "node", "npm", "yarn", "typescript", "react",
    "express", "lodash", "axios", "webpack", "vite", "next",
    "colorama", "jq", "shellcheck", "pylint", "black", "mypy",
    "jest", "eslint",
}


def _load_known_packages() -> set[str]:
    if not _PACKAGES_PATH.exists():
        logger.warning("Known packages list not found at %s", _PACKAGES_PATH)
        return _FALLBACK_PACKAGES
    packages = set()
    for line in _PACKAGES_PATH.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            packages.add(line.lower())
    return packages


KNOWN_GOOD_PACKAGES = _load_known_packages()

_TRUSTED_SCOPES = re.compile(
    r"^@(types|babel|angular|vue|react|next|nuxt|svelte|testing-library|"
    r"typescript-eslint|eslint|prettier|rollup|vitejs|emotion|mui|"
    r"chakra-ui|radix-ui|tanstack|trpc|prisma|nestjs|apollo|graphql-tools|"
    r"aws-sdk|azure|google-cloud|vercel|cloudflare|supabase|firebase)/",
    re.IGNORECASE,
)


@register_rule
class FakeDependency(Rule):
    rule_id = "SOCIAL-001"
    title = "Fake dependency installation"
    description = "Detects instructions to install potentially fake packages"

    _install_patterns = [
        re.compile(r"npm\s+install\s+(?:-g\s+)?([a-z0-9@._/-]+)", re.IGNORECASE),
        re.compile(r"pip\s+install\s+([a-z0-9._-]+)", re.IGNORECASE),
        re.compile(r"brew\s+install\s+([a-z0-9._-]+)", re.IGNORECASE),
        re.compile(r"brew\s+tap\s+[^\s]+\s*&&\s*brew\s+install\s+([a-z0-9._-]+)", re.IGNORECASE),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        skill_md = skill.path / "SKILL.md"
        all_lines: list[tuple[str, int, Path]] = []

        for i, line in enumerate(skill.body.split("\n"), start=1):
            all_lines.append((line, i, skill_md))
        for block in skill.code_blocks:
            for j, line in enumerate(block["content"].split("\n")):
                all_lines.append((line, block["line"] + j, skill_md))
        for bf in skill.bundled_content:
            for k, line in enumerate(bf.content.split("\n"), start=1):
                all_lines.append((line, k, bf.path))

        for line_text, line_num, fpath in all_lines:
            for pat in self._install_patterns:
                m = pat.search(line_text)
                if m:
                    pkg = m.group(1).lower().rstrip("/")
                    if pkg not in KNOWN_GOOD_PACKAGES:
                        if _TRUSTED_SCOPES.match(pkg):
                            continue
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            description=self.description,
                            severity=Severity.HIGH,
                            category=FindingCategory.SOCIAL_ENGINEERING,
                            file_path=fpath,
                            line_number=line_num,
                            matched_content=m.group(0)[:200],
                            remediation=(
                                f'"{pkg}" is not a recognized package. '
                                "Verify before installing."
                            ),
                            reference="1Password analysis (Feb 2026)",
                        ))
        return findings


@register_rule
class FakeErrorMessage(Rule):
    rule_id = "SOCIAL-002"
    title = "Fake error message"
    description = "Detects social engineering via fake error messages prompting command execution"

    _patterns = [
        re.compile(r"if\s+you\s+see\s+an?\s+error.*run\s*:", re.IGNORECASE),
        re.compile(r"to\s+fix\s+this\s+issue.*execute\s*:", re.IGNORECASE),
        re.compile(r"troubleshooting.*paste\s+the\s+following", re.IGNORECASE),
        re.compile(r"if\s+.*fails?\s*,?\s*(run|execute|paste)\s*:", re.IGNORECASE),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_skill_content(skill, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.HIGH,
                category=FindingCategory.SOCIAL_ENGINEERING,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation=(
                    "Be suspicious of skills that instruct you to run "
                    "commands to fix errors."
                ),
                reference="ClawHavoc -- social engineering via fake error messages",
            ))
        return findings


@register_rule
class NpmLifecycleHook(Rule):
    rule_id = "SOCIAL-003"
    title = "Malicious npm lifecycle hook"
    description = "Detects npm preinstall/postinstall hooks that execute shell commands"

    _patterns = [
        re.compile(r'"preinstall"\s*:\s*".*(?:curl|wget|bash|sh|node\s+-e)', re.IGNORECASE),
        re.compile(r'"postinstall"\s*:\s*".*(?:curl|wget|bash|sh|node\s+-e)', re.IGNORECASE),
        re.compile(r'"prepare"\s*:\s*".*(?:curl|wget|bash|sh|node\s+-e)', re.IGNORECASE),
        re.compile(r"child_process.*exec", re.IGNORECASE),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_skill_content(skill, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.CRITICAL,
                category=FindingCategory.SOCIAL_ENGINEERING,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation=(
                    "npm lifecycle hooks (preinstall/postinstall) should not "
                    "execute remote scripts or spawn shell processes."
                ),
                reference=None,
            ))
        return findings
