"""Find automatic execution through package-manager convenience runners.

The helpers in this module only parse text. They never invoke a package manager
or any content from the skill being scanned.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from waingro.models import ParsedSkill
from waingro.rules import SCRIPT_EXTENSIONS, _is_non_executable_line


@dataclass(frozen=True)
class PackageRunnerInvocation:
    file_path: Path
    line_number: int
    runner: str
    package: str
    source_line: str


_RUNNER_NAMES = (
    r"npx(?:\.cmd)?|pnpx(?:\.cmd)?|bunx(?:\.cmd)?|uvx(?:\.exe)?|"
    r"npm(?:\.cmd)?|pipx(?:\.exe)?|yarn(?:\.cmd)?|pnpm(?:\.cmd)?"
)
_ALIAS_RE = re.compile(
    rf"\b(?:const|let|var)\s+(?P<alias>[A-Za-z_$][\w$]*)\s*="
    rf"[^\n;]{{0,240}}?['\"](?P<runner>{_RUNNER_NAMES})['\"]",
    re.IGNORECASE,
)
_JS_ARGV_RE = re.compile(
    rf"\b(?:execFileSync|execFile|spawnSync|spawn|execa)\s*\(\s*"
    rf"(?P<command>[A-Za-z_$][\w$]*|['\"](?:{_RUNNER_NAMES})['\"])\s*,\s*"
    r"\[(?P<args>[\s\S]{0,800}?)\]",
    re.IGNORECASE,
)
_PY_ARGV_RE = re.compile(
    rf"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\(\s*\[\s*"
    rf"['\"](?P<runner>{_RUNNER_NAMES})['\"]\s*,(?P<args>[\s\S]{{0,800}}?)\]",
    re.IGNORECASE,
)
_STRING_EXEC_RE = re.compile(
    r"\b(?:execSync|exec|system)\s*\(\s*(?P<quote>['\"])(?P<command>[^'\"\n]{1,800})(?P=quote)",
    re.IGNORECASE,
)
_QUOTED_TOKEN_RE = re.compile(r"(['\"])(?P<token>.*?)(?<!\\)\1")
_SHELL_RUNNER_RE = re.compile(
    rf"^\s*(?:sudo\s+)?(?P<runner>{_RUNNER_NAMES})\b(?P<args>.*)$",
    re.IGNORECASE,
)
_EXACT_SEMVER_RE = re.compile(
    r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_FULL_COMMIT_RE = re.compile(r"#[0-9a-f]{40}$", re.IGNORECASE)
_NO_NETWORK_FLAGS = {"--no-install", "--offline"}
_FLAG_VALUE_OPTIONS = {
    "--cache",
    "--call",
    "--node-options",
    "--registry",
    "--userconfig",
}


def _normalise_runner(value: str) -> str:
    return value.lower().removesuffix(".cmd").removesuffix(".exe")


def _quoted_tokens(value: str) -> list[str]:
    return [match.group("token") for match in _QUOTED_TOKEN_RE.finditer(value)]


def _command_tokens(value: str) -> list[str]:
    try:
        return shlex.split(value, comments=False, posix=True)
    except ValueError:
        return []


def _package_selector(runner: str, args: list[str]) -> str | None:
    """Return the package selector that a runner may resolve remotely."""
    runner = _normalise_runner(runner)
    if not args or any(flag in args for flag in _NO_NETWORK_FLAGS):
        return None

    position = 0
    if runner == "npm":
        if args[0] not in {"exec", "x"}:
            return None
        position = 1
    elif runner in {"yarn", "pnpm"}:
        if args[0] != "dlx":
            return None
        position = 1
    elif runner == "pipx":
        if args[0] != "run":
            return None
        position = 1

    while position < len(args):
        argument = args[position]
        if argument in {"-p", "--package"} and position + 1 < len(args):
            return args[position + 1]
        if argument.startswith("--package="):
            return argument.split("=", 1)[1]
        if argument in _FLAG_VALUE_OPTIONS:
            position += 2
            continue
        if argument == "--" or argument.startswith("-"):
            position += 1
            continue
        return argument
    return None


def _is_immutable_selector(selector: str) -> bool:
    if selector.startswith((".", "/", "file:")):
        return True
    if _FULL_COMMIT_RE.search(selector):
        return True
    if selector.startswith("@"):
        separator = selector.rfind("@")
        version = selector[separator + 1 :] if separator > 0 else ""
    elif "@" in selector:
        version = selector.rsplit("@", 1)[1]
    else:
        return False
    return bool(_EXACT_SEMVER_RE.fullmatch(version))


def _append_if_unpinned(
    findings: list[PackageRunnerInvocation],
    *,
    file_path: Path,
    line_number: int,
    runner: str,
    args: list[str],
    source_line: str,
) -> None:
    selector = _package_selector(runner, args)
    if selector and not _is_immutable_selector(selector):
        findings.append(
            PackageRunnerInvocation(
                file_path=file_path,
                line_number=line_number,
                runner=_normalise_runner(runner),
                package=selector,
                source_line=source_line.strip(),
            )
        )


def find_unpinned_package_runners(skill: ParsedSkill) -> list[PackageRunnerInvocation]:
    """Find automatic, unpinned package-runner calls in bundled scripts."""
    findings: list[PackageRunnerInvocation] = []
    for bundled in skill.bundled_content:
        suffix = bundled.path.suffix.lower()
        if suffix not in SCRIPT_EXTENSIONS:
            continue
        content = bundled.content
        aliases = {
            match.group("alias"): _normalise_runner(match.group("runner"))
            for match in _ALIAS_RE.finditer(content)
        }

        for match in _JS_ARGV_RE.finditer(content):
            raw_command = match.group("command")
            runner = raw_command.strip("'\"")
            if raw_command[0] not in "'\"":
                runner = aliases.get(raw_command, "")
            if not runner:
                continue
            line_number = content.count("\n", 0, match.start()) + 1
            source_line = content.splitlines()[line_number - 1]
            if _is_non_executable_line(source_line, bundled.path):
                continue
            _append_if_unpinned(
                findings,
                file_path=bundled.path,
                line_number=line_number,
                runner=runner,
                args=_quoted_tokens(match.group("args")),
                source_line=source_line,
            )

        for match in _PY_ARGV_RE.finditer(content):
            line_number = content.count("\n", 0, match.start()) + 1
            source_line = content.splitlines()[line_number - 1]
            if _is_non_executable_line(source_line, bundled.path):
                continue
            _append_if_unpinned(
                findings,
                file_path=bundled.path,
                line_number=line_number,
                runner=match.group("runner"),
                args=_quoted_tokens(match.group("args")),
                source_line=source_line,
            )

        for match in _STRING_EXEC_RE.finditer(content):
            tokens = _command_tokens(match.group("command"))
            if not tokens or not re.fullmatch(_RUNNER_NAMES, tokens[0], re.IGNORECASE):
                continue
            line_number = content.count("\n", 0, match.start()) + 1
            source_line = content.splitlines()[line_number - 1]
            if _is_non_executable_line(source_line, bundled.path):
                continue
            _append_if_unpinned(
                findings,
                file_path=bundled.path,
                line_number=line_number,
                runner=tokens[0],
                args=tokens[1:],
                source_line=source_line,
            )

        if suffix in {".sh", ".bash", ".zsh"}:
            for line_number, source_line in enumerate(content.splitlines(), start=1):
                if _is_non_executable_line(source_line, bundled.path):
                    continue
                match = _SHELL_RUNNER_RE.match(source_line)
                if not match:
                    continue
                _append_if_unpinned(
                    findings,
                    file_path=bundled.path,
                    line_number=line_number,
                    runner=match.group("runner"),
                    args=_command_tokens(match.group("args")),
                    source_line=source_line,
                )

    seen: set[tuple[Path, int, str, str]] = set()
    deduped = []
    for finding in findings:
        key = (finding.file_path, finding.line_number, finding.runner, finding.package)
        if key not in seen:
            seen.add(key)
            deduped.append(finding)
    return deduped
