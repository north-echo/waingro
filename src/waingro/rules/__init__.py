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


_COMMENT_RE = re.compile(r"^\s*#(?!!)")  # shell/python comments (not shebangs #!)
_JS_COMMENT_RE = re.compile(r"^\s*//")  # JS/TS single-line comments
_STRING_CONTEXT_RE = re.compile(
    r"""(?:die|echo|print|printf|warn|error|log|msg|message|usage|help)\s*[("]\s*.*$""",
    re.IGNORECASE,
)

SCRIPT_EXTENSIONS = {".sh", ".bash", ".zsh", ".py", ".js", ".ts", ".mjs", ".cjs"}


def _is_non_executable_line(line: str, file_path: Path | None = None) -> bool:
    """Check if a line is a comment or string-literal context in a script file."""
    if file_path and file_path.suffix in SCRIPT_EXTENSIONS:
        stripped = line.lstrip()
        # Shell/Python comments (but not shebangs)
        if _COMMENT_RE.match(stripped):
            return True
        # JS/TS comments
        if file_path.suffix in (".js", ".ts", ".mjs", ".cjs") and _JS_COMMENT_RE.match(stripped):
            return True
    # Error message / help text context (any file type)
    return bool(_STRING_CONTEXT_RE.match(line.lstrip()))


def search_skill_content(
    skill: ParsedSkill, patterns: list[re.Pattern],
) -> list[tuple[str, int | None, Path]]:
    """Search body, code blocks, and bundled files for pattern matches.

    Skips comment lines and string-literal contexts in bundled scripts.
    Returns (matched_text, line_number, file_path) tuples.
    """
    hits: list[tuple[str, int | None, Path]] = []
    skill_md = skill.path / "SKILL.md"

    # Search body (markdown — no comment filtering)
    for i, line in enumerate(skill.body.split("\n"), start=1):
        for pat in patterns:
            m = pat.search(line)
            if m:
                hits.append((m.group(0), i, skill_md))

    # Search code blocks (inside SKILL.md — no comment filtering,
    # these are agent instructions)
    for block in skill.code_blocks:
        for j, line in enumerate(block["content"].split("\n")):
            for pat in patterns:
                m = pat.search(line)
                if m:
                    hits.append((m.group(0), block["line"] + j, skill_md))

    # Search bundled file content (with comment/string-literal filtering)
    for bf in skill.bundled_content:
        for k, line in enumerate(bf.content.split("\n"), start=1):
            if _is_non_executable_line(line, bf.path):
                continue
            for pat in patterns:
                m = pat.search(line)
                if m:
                    hits.append((m.group(0), k, bf.path))

    return hits
