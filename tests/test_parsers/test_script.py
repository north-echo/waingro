"""Tests for script parser."""

import tempfile
from pathlib import Path

from waingro.parsers.script import get_script_lines, read_script


def test_read_script():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/bash\necho hello\n")
        f.flush()
        content = read_script(Path(f.name))
    assert "echo hello" in content


def test_get_script_lines():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("line1\nline2\nline3\n")
        f.flush()
        lines = get_script_lines(Path(f.name))
    assert lines[0] == (1, "line1")
    assert lines[1] == (2, "line2")
    assert len(lines) == 4  # includes trailing empty
