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


def code_block_body_lines(skill: ParsedSkill) -> set[int]:
    """Return 1-based *body* line numbers already covered by ``skill.code_blocks``.

    Fenced-block content is searched separately via ``skill.code_blocks``;
    scanning the same lines again in the body pass reports every match twice.
    Spans are derived from the blocks themselves rather than by re-scanning for
    fences, so a hand-built ParsedSkill whose ``code_blocks`` is empty keeps
    full body coverage, and an unterminated fence (which yields no block) is
    still searched.
    """
    covered: set[int] = set()
    offset = skill.frontmatter_lines
    for block in skill.code_blocks:
        start = block.get("line")
        if start is None:
            continue
        n_lines = len(block["content"].split("\n"))
        # block["line"] is file-relative; convert back to body coordinates.
        body_start = start - offset
        covered.update(range(body_start, body_start + n_lines))
    return covered


def search_skill_content(
    skill: ParsedSkill, patterns: list[re.Pattern],
) -> list[tuple[str, int | None, Path]]:
    """Search body, code blocks, and bundled files for pattern matches.

    Skips comment lines and string-literal contexts in bundled scripts.
    Returns (matched_text, line_number, file_path) tuples. Line numbers for
    SKILL.md are file-relative (frontmatter included). Duplicate hits for the
    same rule at the same location are collapsed.
    """
    hits: list[tuple[str, int | None, Path]] = []
    skill_md = skill.path / "SKILL.md"

    # Search body (markdown — no comment filtering). Fenced blocks are skipped
    # here because they are searched separately below via skill.code_blocks.
    covered = code_block_body_lines(skill)
    offset = skill.frontmatter_lines
    for i, line in enumerate(skill.body.split("\n"), start=1):
        if i in covered:
            continue
        for pat in patterns:
            m = pat.search(line)
            if m:
                hits.append((m.group(0), i + offset, skill_md))

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

    # Collapse identical (text, line, file) hits produced by overlapping
    # patterns within the same rule, preserving first-seen order.
    seen: set[tuple[str, int | None, Path]] = set()
    deduped: list[tuple[str, int | None, Path]] = []
    for hit in hits:
        if hit in seen:
            continue
        seen.add(hit)
        deduped.append(hit)
    return deduped
