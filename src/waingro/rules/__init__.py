"""Rule base class and registry."""

import re
from abc import ABC, abstractmethod
from pathlib import Path

from waingro.models import Finding, ParsedSkill

_RULES: list[type["Rule"]] = []


class Rule(ABC):
    """Base class for all detection rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique rule identifier, e.g. EXEC-001"""

    @property
    @abstractmethod
    def title(self) -> str:
        """Human-readable rule name"""

    @property
    @abstractmethod
    def description(self) -> str:
        """What this rule detects"""

    @abstractmethod
    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        """Run the rule against a parsed skill. Return findings."""


def register_rule(cls: type[Rule]) -> type[Rule]:
    """Decorator to register a rule class."""
    _RULES.append(cls)
    return cls


def get_all_rules() -> list[Rule]:
    """Instantiate and return all registered rules."""
    return [cls() for cls in _RULES]


def search_skill_content(
    skill: ParsedSkill, patterns: list[re.Pattern],
) -> list[tuple[str, int | None, Path]]:
    """Search body, code blocks, and bundled files for pattern matches.

    Returns (matched_text, line_number, file_path) tuples.
    """
    hits: list[tuple[str, int | None, Path]] = []
    skill_md = skill.path / "SKILL.md"

    # Search body
    for i, line in enumerate(skill.body.split("\n"), start=1):
        for pat in patterns:
            m = pat.search(line)
            if m:
                hits.append((m.group(0), i, skill_md))

    # Search code blocks
    for block in skill.code_blocks:
        for j, line in enumerate(block["content"].split("\n")):
            for pat in patterns:
                m = pat.search(line)
                if m:
                    hits.append((m.group(0), block["line"] + j, skill_md))

    # Search bundled file content
    for bf in skill.bundled_content:
        for k, line in enumerate(bf.content.split("\n"), start=1):
            for pat in patterns:
                m = pat.search(line)
                if m:
                    hits.append((m.group(0), k, bf.path))

    return hits
