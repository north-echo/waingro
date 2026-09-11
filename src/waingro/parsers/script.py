"""Read bundled files without following a final symlink."""

import os
import stat
from pathlib import Path


def read_file_bytes(path: Path) -> bytes:
    """Read stable bytes from one regular file and reject replacement while open."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"file could not be opened safely: {path}") from exc
    chunks = []
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"path is not a regular file: {path}")
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    content = b"".join(chunks)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or len(content) != after.st_size:
        raise ValueError(f"file changed while it was read: {path}")
    return content


def read_script(path: Path) -> str:
    """Read a script file and return its contents."""
    return read_file_bytes(path).decode("utf-8", errors="replace")


def get_script_lines(path: Path) -> list[tuple[int, str]]:
    """Read a script file and return numbered lines as (line_number, content) tuples."""
    content = read_script(path)
    return [(i + 1, line) for i, line in enumerate(content.split("\n"))]
