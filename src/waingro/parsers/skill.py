"""Parse SKILL.md files: extract YAML frontmatter, markdown body, and code blocks."""

import hashlib
import re
from pathlib import Path

import yaml

from waingro.models import ParsedSkill, SkillMetadata
from waingro.parsers.script import read_file_bytes
from waingro.parsers.sections import parse_sections

FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
CODE_BLOCK_RE = re.compile(r"^```(\w*)\n(.*?)^```", re.MULTILINE | re.DOTALL)
BUNDLED_EXTENSIONS = {
    ".bash",
    ".cjs",
    ".js",
    ".json",
    ".md",
    ".mjs",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".txt",
    ".yaml",
    ".yml",
    ".zsh",
}
MAX_BUNDLED_DEPTH = 2


def _optional_text(value) -> str | None:
    return value if isinstance(value, str) else None


def _string_list(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def parse_frontmatter(content: str) -> tuple[dict, str]:
    """Extract YAML frontmatter and return (metadata_dict, body)."""
    match = FRONTMATTER_RE.match(content)
    if not match:
        return {}, content
    raw_yaml = match.group(1)
    body = content[match.end() :]
    try:
        metadata = yaml.safe_load(raw_yaml) or {}
    except yaml.YAMLError:
        metadata = {}
    if not isinstance(metadata, dict):
        metadata = {}
    return metadata, body


def extract_code_blocks(content: str, start_line_offset: int = 0) -> list[dict]:
    """Extract fenced code blocks with language and line numbers.

    ``line`` is the 1-based line of the block's *first content line* (the line
    after the opening fence), already shifted by ``start_line_offset`` so it is
    file-relative. Consumers index content lines as ``block["line"] + j``.
    """
    blocks = []
    lines = content.split("\n")
    in_block = False
    block_lang = ""
    block_lines: list[str] = []
    block_start = 0

    for i, line in enumerate(lines):
        if not in_block and line.startswith("```"):
            in_block = True
            block_lang = line[3:].strip()
            block_lines = []
            block_start = i + 2 + start_line_offset  # first line after the fence
        elif in_block and line.startswith("```"):
            blocks.append(
                {
                    "language": block_lang,
                    "content": "\n".join(block_lines),
                    "line": block_start,
                }
            )
            in_block = False
        elif in_block:
            block_lines.append(line)

    return blocks


def discover_bundled_files(skill_dir: Path) -> list[Path]:
    """Find relevant bundled files no more than two levels below a skill.

    Markdown and text resources are executable input in an agent skill when the
    root instructions tell the agent to consume them. Conversely, unbounded
    recursion pulls nested fixtures, vendored projects, and backups into the
    parent skill's verdict. The two-level boundary covers ordinary ``scripts/``
    and ``references/`` layouts without conflating nested projects.
    """
    files = []
    if not skill_dir.is_dir():
        return files
    root = skill_dir.resolve()
    for ext in sorted(BUNDLED_EXTENSIONS):
        for path in sorted(skill_dir.rglob(f"*{ext}")):
            if path.is_symlink() or not path.is_file():
                continue
            try:
                lexical_relative = path.relative_to(skill_dir)
            except ValueError:
                continue
            cursor = skill_dir
            if any(
                (cursor := cursor / part).is_symlink()
                for part in lexical_relative.parts
            ):
                continue
            try:
                relative = path.resolve().relative_to(root)
            except ValueError:
                continue
            if path.name.lower() == "skill.md" or len(relative.parts) > MAX_BUNDLED_DEPTH:
                continue
            files.append(path)
    return files


def parse_skill(path: Path) -> ParsedSkill:
    """Parse a skill directory or SKILL.md file into a ParsedSkill."""
    if path.is_symlink():
        raise ValueError(f"symlinked skill paths are not accepted: {path}")
    if path.is_dir():
        skill_md = path / "SKILL.md"
        skill_dir = path
    else:
        if path.name != "SKILL.md":
            raise ValueError(f"expected a skill directory or SKILL.md, got: {path}")
        skill_md = path
        skill_dir = path.parent

    if skill_md.is_symlink():
        raise ValueError(f"symlinked SKILL.md is not accepted: {skill_md}")
    if not skill_md.is_file():
        raise FileNotFoundError(f"SKILL.md not found: {skill_md}")

    raw_content = read_file_bytes(skill_md)
    content = raw_content.decode("utf-8", errors="replace")
    raw_meta, body = parse_frontmatter(content)

    # Count frontmatter lines for offset
    fm_match = FRONTMATTER_RE.match(content)
    fm_lines = content[: fm_match.end()].count("\n") if fm_match else 0

    raw_name = raw_meta.get("name")
    metadata = SkillMetadata(
        name=raw_name if isinstance(raw_name, str) and raw_name else skill_dir.name,
        description=_optional_text(raw_meta.get("description")),
        version=_optional_text(raw_meta.get("version")),
        author=_optional_text(raw_meta.get("author")),
        tags=_string_list(raw_meta.get("tags")),
        tools=_string_list(raw_meta.get("tools")),
        raw_frontmatter=raw_meta,
    )

    code_blocks = extract_code_blocks(body, start_line_offset=fm_lines)
    bundled_files = discover_bundled_files(skill_dir)
    sections = parse_sections(body, start_line_offset=fm_lines)

    return ParsedSkill(
        path=skill_dir,
        metadata=metadata,
        body=body,
        code_blocks=code_blocks,
        bundled_files=bundled_files,
        sections=sections,
        frontmatter_lines=fm_lines,
        manifest_sha256=hashlib.sha256(raw_content).hexdigest(),
        manifest_size_bytes=len(raw_content),
    )
