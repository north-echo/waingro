"""Parse bundled script files (.sh, .py, .js) for analysis."""

from pathlib import Path


def read_script(path: Path) -> str:
    """Read a script file and return its contents."""
    return path.read_text(encoding="utf-8", errors="replace")


def get_script_lines(path: Path) -> list[tuple[int, str]]:
    """Read a script file and return numbered lines as (line_number, content) tuples."""
    content = read_script(path)
    return [(i + 1, line) for i, line in enumerate(content.split("\n"))]
