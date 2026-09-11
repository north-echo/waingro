"""Markdown section parser with heading classification."""

from __future__ import annotations

import re
from dataclasses import dataclass

HEADING_RE = re.compile(r"^(#{1,6})\s+(.+)$")
FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})")

USAGE_HEADINGS = {
    "usage",
    "quick start",
    "how to use",
    "getting started",
    "commands",
    "installation",
    "setup",
    "run",
    "execute",
    "how it works",
}

DETECTION_HEADINGS = {
    "what it detects",
    "detection patterns",
    "blocked patterns",
    "instant block",
    "threat categories",
    "blacklist",
    "threat model",
    "attack patterns",
    "security checks",
    "risk assessment",
    "examples of malicious",
    "known threats",
    "threat database",
    "blacklist_patterns",
    "what it catches",
    "defense protocol",
    "detection engines",
    "security rules",
    "red flag",
    "obfuscated code",
    "credential theft",
    "危险标志",
    "安全检查",
    "安全规则",
    "检测模式",
    "拦截规则",
}

DOCUMENTATION_HEADINGS = {
    "about",
    "description",
    "overview",
    "architecture",
    "features",
}

CONFIGURATION_HEADINGS = {
    "configuration",
    "config",
    "settings",
    "options",
    "environment variables",
}


@dataclass
class MarkdownSection:
    heading: str
    level: int
    start_line: int
    end_line: int
    category: str  # "usage", "detection", "documentation", "configuration", "unknown"
    parent_heading: str | None


def classify_heading(heading: str) -> str:
    """Classify a heading into a semantic category."""
    h = heading.lower().strip()
    for pattern in DETECTION_HEADINGS:
        if pattern in h:
            return "detection"
    for pattern in USAGE_HEADINGS:
        if pattern in h:
            return "usage"
    for pattern in DOCUMENTATION_HEADINGS:
        if pattern in h:
            return "documentation"
    for pattern in CONFIGURATION_HEADINGS:
        if pattern in h:
            return "configuration"
    return "unknown"


def parse_sections(body: str, start_line_offset: int = 0) -> list[MarkdownSection]:
    """Parse markdown body into sections with heading classification."""
    lines = body.split("\n")
    sections: list[MarkdownSection] = []
    heading_stack: list[tuple[int, str, str]] = []  # (level, heading, category)
    fence_character: str | None = None
    fence_length = 0

    for i, line in enumerate(lines):
        fence = FENCE_RE.match(line)
        if fence:
            marker = fence.group(1)
            if fence_character is None:
                fence_character = marker[0]
                fence_length = len(marker)
            elif marker[0] == fence_character and len(marker) >= fence_length:
                fence_character = None
                fence_length = 0
            continue
        if fence_character is not None:
            continue

        m = HEADING_RE.match(line)
        if not m:
            continue

        level = len(m.group(1))
        heading = m.group(2).strip()
        line_num = i + 1 + start_line_offset

        # Close previous section at this level or lower
        if sections:
            sections[-1].end_line = line_num - 1

        # Update heading stack for parent tracking
        while heading_stack and heading_stack[-1][0] >= level:
            heading_stack.pop()
        parent = heading_stack[-1][1] if heading_stack else None
        category = classify_heading(heading)
        if category == "unknown" and heading_stack:
            parent_category = heading_stack[-1][2]
            if parent_category == "detection":
                category = parent_category
        heading_stack.append((level, heading, category))

        sections.append(
            MarkdownSection(
                heading=heading,
                level=level,
                start_line=line_num,
                end_line=len(lines) + start_line_offset,  # default to end
                category=category,
                parent_heading=parent,
            )
        )

    # Close last section
    if sections:
        sections[-1].end_line = len(lines) + start_line_offset

    return sections


def find_section_for_line(
    sections: list[MarkdownSection],
    line_number: int,
) -> MarkdownSection | None:
    """Find the section containing a given line number."""
    for section in reversed(sections):
        if section.start_line <= line_number <= section.end_line:
            return section
    return None
