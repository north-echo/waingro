"""Social engineering rules: detect fake dependencies and misleading error messages."""

import logging
import re
from pathlib import Path

from waingro.analyzers.typosquat import _levenshtein
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


# Impersonating the platform is a different attack from typosquatting a
# package, and edit distance cannot see it: "openclaw-core" is nowhere near any
# real package name, it just sounds like the runtime the skill claims to need.
# This is the 1Password-documented shape - invent a plausible first-party
# dependency and let the agent install it.
_PLATFORM_BRANDS = re.compile(
    r"(?:^|[-_@/])(?:openclaw|clawhub|clawd|clawdbot|anthropic|claude)(?:$|[-_./])",
    re.IGNORECASE,
)


# Names too short to typosquat meaningfully - a 1-edit neighbourhood of a
# 3-character name is most of the registry.
_MIN_TYPOSQUAT_LEN = 5


def _nearest_known(pkg: str, threshold: int = 2) -> str | None:
    """Return a known package within `threshold` edits of `pkg`, else None."""
    if len(pkg) < _MIN_TYPOSQUAT_LEN:
        return None
    best, best_dist = None, threshold + 1
    for good in KNOWN_GOOD_PACKAGES:
        if abs(len(good) - len(pkg)) > threshold or len(good) < _MIN_TYPOSQUAT_LEN:
            continue
        dist = _levenshtein(pkg, good)
        if 0 < dist < best_dist:
            best, best_dist = good, dist
    return best

@register_rule
class FakeDependency(Rule):
    rule_id = "SOCIAL-001"
    title = "Fake dependency installation"
    description = "Detects instructions to install potentially fake packages"

    _install_patterns = [
        re.compile(r"npm\s+install\s+(?:-[gGSD]\s+)*([a-z@][a-z0-9@._/-]+)", re.IGNORECASE),
        re.compile(r"pip\s+install\s+(?:-[^\s]+\s+)*([a-z][a-z0-9._-]+)", re.IGNORECASE),
        re.compile(r"brew\s+install\s+(?:--[a-z-]+\s+)*([a-z][a-z0-9._-]+)", re.IGNORECASE),
        re.compile(
            r"brew\s+tap\s+[^\s]+\s*&&\s*brew\s+install\s+([a-z][a-z0-9._-]+)",
            re.IGNORECASE,
        ),
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
                    # Skip file references (pip install -r requirements.txt)
                    if "." in pkg and pkg.rsplit(".", 1)[-1] in (
                        "txt", "cfg", "toml", "in", "lock", "yml", "yaml",
                    ):
                        continue
                    if pkg not in KNOWN_GOOD_PACKAGES:
                        if _TRUSTED_SCOPES.match(pkg):
                            continue

                        # The allowlist holds a few hundred names against
                        # ecosystems of millions, so "not on the list" is not
                        # evidence of anything: pyzotero and pptxgenjs are real.
                        # What the rule is actually for is typosquatting, and
                        # that has a signal - a name one or two edits from a
                        # popular package. Grade on that, not on membership.
                        near = _nearest_known(pkg)
                        if _PLATFORM_BRANDS.search(pkg):
                            severity, confidence = Severity.HIGH, 0.8
                            remediation = (
                                f'"{pkg}" is presented as a first-party component '
                                "but is not a recognized package. Verify that it "
                                "exists and is published by the platform."
                            )
                            note = (
                                "Unrecognised package whose name claims platform "
                                "affiliation."
                            )
                        elif near:
                            severity, confidence = Severity.HIGH, 0.85
                            remediation = (
                                f'"{pkg}" is one or two characters from "{near}", '
                                "a widely used package. Verify before installing."
                            )
                            note = f"Possible typosquat of {near}."
                        else:
                            severity, confidence = Severity.LOW, 0.2
                            remediation = (
                                f'"{pkg}" is not in the known-package list. '
                                "That alone is not suspicious; verify if unfamiliar."
                            )
                            note = (
                                "Unrecognised package name with no close match to a "
                                "known package. Informational only."
                            )
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            description=self.description,
                            severity=severity,
                            category=FindingCategory.SOCIAL_ENGINEERING,
                            file_path=fpath,
                            line_number=line_num,
                            matched_content=m.group(0)[:200],
                            remediation=remediation,
                            reference="1Password analysis (Feb 2026)",
                            confidence=confidence,
                            context_note=note,
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
