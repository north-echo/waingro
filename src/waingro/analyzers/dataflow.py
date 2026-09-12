"""Conservative lexical data-flow checks for decode/fetch-to-execution rules.

These helpers deliberately answer a narrow question: does the value produced by
the source expression reach an execution sink in the same statement or lexical
function scope? Merely placing a source and a sink in the same file, context
window, or minified line is not a flow.

This is not a general program-analysis engine. When the relationship cannot be
established from a direct nesting, an assignment, and a later exact-name use,
the result is false. Static signatures must not turn uncertainty into an attack.
"""

from __future__ import annotations

import io
import re
import tokenize
from pathlib import Path

from waingro.models import ParsedSkill

LOCKFILE_NAMES = {
    "bun.lock",
    "bun.lockb",
    "cargo.lock",
    "composer.lock",
    "gemfile.lock",
    "package-lock.json",
    "pipfile.lock",
    "pnpm-lock.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "yarn.lock",
}

_VENDORED_PARTS = {
    ".venv",
    "node_modules",
    "site-packages",
    "third_party",
    "venv",
    "vendor",
    "vendors",
    "vendored",
}
_GENERATED_NAMES = {"bundle.js", "bundle.css", "vendor.js", "vendor.css"}
MAX_CORRELATION_LINE = 2_000

LIFECYCLE_EXEC_OR_FETCH_RE = re.compile(
    r"(?:"
    r"\b(?:curl|wget|Invoke-WebRequest|iwr)\b|DownloadString\s*\(|"
    r"\bfetch\s*\(\s*['\"]https?://|"
    r"child_process[^\n;&|]*\.(?:exec|execSync|spawn|spawnSync)\s*\(|"
    r"\b(?:subprocess|os\.(?:system|popen))\b|"
    r"\b(?:exec|execSync|spawn|spawnSync|eval)\s*\("
    r")",
    re.IGNORECASE,
)

# Calls that consume a command or source string and execute it. Imports and bare
# module names are intentionally absent: ``import subprocess`` is not a sink.
EXECUTION_SINK_RE = re.compile(
    r"""(?:
        \b(?:eval|exec)\s*\(
      | (?:^|\n)\s*(?:eval|exec)\s+
      | \b(?:system|popen|passthru|proc_open)\s*\(
      | \bos\.system\s*\(
      | \bos\.popen\s*\(
      | \bsubprocess\.(?:call|run|Popen|check_call|check_output)\s*\(
      | \bchild_process\.(?:exec|execSync|spawn|spawnSync)\s*\(
      | \brequire\s*\(\s*['\"]child_process['\"]\s*\)
          \s*\.\s*(?:exec|execSync|spawn|spawnSync)\s*\(
      | \b(?:exec|execSync|spawn|spawnSync)\s*\(
      | \b(?-i:Function)\s*\(
      | \b(?:bash|sh|zsh|dash|powershell|pwsh)\s+-c\b
      | \b(?:iex|invoke-expression)\b
    )""",
    re.IGNORECASE | re.VERBOSE,
)

_PIPE_SHELL_RE = re.compile(
    r"\|\s*(?:bash|sh|zsh|dash)(?=\s|$|[`'\"])",
    re.IGNORECASE,
)
_ASSIGNMENT_RE = re.compile(
    r"(?:^|[;{]\s*)\s*(?:(?:const|let|var|local|export)\s+)?"
    r"([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=(?!=)",
)
_PY_FUNCTION_RE = re.compile(r"^(\s*)(?:async\s+def|def)\s+[A-Za-z_]\w*\s*\(")
_BRACE_FUNCTION_RE = re.compile(
    r"(?:\bfunction\b|\([^)]*\)\s*=>\s*\{|"
    r"\b(?!(?:if|for|while|switch|catch|with)\b)[A-Za-z_$][\w$]*\s*\([^)]*\)\s*\{)"
)
_FENCE_RE = re.compile(r"^\s*```")


def is_generated_or_vendored(path: Path, content: str) -> bool:
    """Return whether line-local correlation is unreliable for this file."""
    name = path.name.lower()
    if name == "skill.md":
        return False
    if name in LOCKFILE_NAMES or name in _GENERATED_NAMES:
        return True
    if name.endswith((".min.js", ".min.css")):
        return True
    if any(part.lower() in _VENDORED_PARTS for part in path.parts):
        return True
    return any(len(line) > MAX_CORRELATION_LINE for line in content.splitlines())


def _skill_cache(skill: ParsedSkill) -> dict[tuple[object, ...], object]:
    """Return an analysis-lifetime cache without retaining input after the scan."""
    cache = getattr(skill, "_waingro_dataflow_cache", None)
    if cache is None:
        cache = {}
        skill._waingro_dataflow_cache = cache
    return cache


def _is_generated_or_vendored(
    skill: ParsedSkill,
    path: Path,
    content: str,
) -> bool:
    """Cache an otherwise whole-file check for repeated finding correlation."""
    cache = _skill_cache(skill)
    key = ("generated-or-vendored", path, id(content))
    cached = cache.get(key)
    if isinstance(cached, bool):
        return cached
    result = is_generated_or_vendored(path, content)
    cache[key] = result
    return result


def _content_lines(skill: ParsedSkill, content: str) -> list[str]:
    """Split immutable source once per scan instead of once per finding."""
    cache = _skill_cache(skill)
    key = ("content-lines", id(content))
    cached = cache.get(key)
    if isinstance(cached, list):
        return cached
    lines = content.splitlines()
    cache[key] = lines
    return lines


def _source_for_finding(
    skill: ParsedSkill,
    file_path: Path,
    line_number: int | None,
) -> tuple[str, int]:
    """Return source text and the file line immediately before its first line."""
    if file_path.name == "SKILL.md":
        if line_number is not None:
            for block in skill.code_blocks:
                first = int(block.get("line", 1))
                count = len(block.get("content", "").splitlines())
                if first <= line_number < first + count:
                    return block.get("content", ""), first - 1
        return skill.body, skill.frontmatter_lines

    for bundled in skill.bundled_content:
        if bundled.path == file_path:
            return bundled.content, 0
    return "", 0


def _without_python_strings_and_comments(
    content: str,
    *,
    mask_strings: bool = True,
) -> str:
    """Mask Python comments and optionally strings while preserving layout."""
    lines = [list(line) for line in content.splitlines(keepends=True)]
    try:
        tokens = tokenize.generate_tokens(io.StringIO(content).readline)
        for token in tokens:
            masked_types = {tokenize.COMMENT}
            if mask_strings:
                masked_types.add(tokenize.STRING)
            if token.type not in masked_types:
                continue
            start_line, start_col = token.start
            end_line, end_col = token.end
            for line_number in range(start_line, end_line + 1):
                if not 1 <= line_number <= len(lines):
                    continue
                line = lines[line_number - 1]
                first = start_col if line_number == start_line else 0
                last = end_col if line_number == end_line else len(line)
                for column in range(first, min(last, len(line))):
                    if line[column] not in ("\n", "\r"):
                        line[column] = " "
    except (IndentationError, tokenize.TokenError):
        # The tokens yielded before malformed input remain masked. The scanner
        # then continues conservatively instead of dropping the whole file.
        pass
    return "".join("".join(line) for line in lines)


def _without_c_block_comments(content: str) -> str:
    """Mask C-style block comments while preserving strings and line layout."""
    output = list(content)
    quote: str | None = None
    escaped = False
    in_comment = False
    index = 0
    while index < len(content):
        character = content[index]
        following = content[index + 1] if index + 1 < len(content) else ""
        if in_comment:
            if character == "*" and following == "/":
                if output[index] not in ("\n", "\r"):
                    output[index] = " "
                if output[index + 1] not in ("\n", "\r"):
                    output[index + 1] = " "
                in_comment = False
                index += 2
                continue
            if character not in ("\n", "\r"):
                output[index] = " "
            index += 1
            continue
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif quote:
            if character == quote:
                quote = None
        elif character in ("'", '"', "`"):
            quote = character
        elif character == "/" and following == "*":
            output[index] = " "
            output[index + 1] = " "
            in_comment = True
            index += 2
            continue
        index += 1
    return "".join(output)


def _statement_bounds(lines: list[str], index: int) -> tuple[int, int]:
    """Find a small logical statement containing ``index`` (end exclusive)."""
    start = index
    # A decode call commonly starts on a continuation line. Walk back while the
    # preceding text has an unmatched opening delimiter or explicit continuation.
    for candidate in range(index - 1, max(-1, index - 30), -1):
        # Once a multiline expression opener has been found, do not absorb a
        # preceding control-flow block merely because the expression has not
        # closed yet at the finding line.  Crossing that boundary can join a
        # sink from an earlier function or branch to an unrelated source.
        if start < index and (
            not lines[candidate].strip()
            or lines[candidate].rstrip().endswith(":")
        ):
            break
        prefix = "\n".join(lines[candidate : index + 1])
        if (
            prefix.count("(") > prefix.count(")")
            or prefix.count("[") > prefix.count("]")
            or lines[candidate].rstrip().endswith(("\\", "(", "[", ","))
        ):
            start = candidate
            continue
        break

    end = index + 1
    text = "\n".join(lines[start:end])
    while end < len(lines) and end - start < 60:
        if (
            text.count("(") <= text.count(")")
            and text.count("[") <= text.count("]")
            and not lines[end - 1].rstrip().endswith(("\\", "(", "[", ","))
        ):
            break
        text += "\n" + lines[end]
        end += 1
    return start, end


def _fenced_bounds(lines: list[str], index: int) -> tuple[int, int]:
    fences = [i for i, line in enumerate(lines) if _FENCE_RE.match(line)]
    previous = [i for i in fences if i < index]
    if not previous or len(previous) % 2 == 0:
        return 0, len(lines)
    start = previous[-1] + 1
    end = next((i for i in fences if i > index), len(lines))
    return start, end


def _python_scope(lines: list[str], index: int, lower: int, upper: int) -> tuple[int, int]:
    current_indent = len(lines[index]) - len(lines[index].lstrip())
    for i in range(index - 1, lower - 1, -1):
        match = _PY_FUNCTION_RE.match(lines[i])
        if not match:
            continue
        indent = len(match.group(1))
        if indent >= current_indent:
            continue
        # A same-or-lower indentation between the function and the target would
        # mean the target is no longer inside that function.
        escaped = any(
            line.strip()
            and not line.lstrip().startswith(("#", "@"))
            and len(line) - len(line.lstrip()) <= indent
            for line in lines[i + 1 : index]
        )
        if escaped:
            continue
        end = upper
        for j in range(index + 1, upper):
            line = lines[j]
            if (
                line.strip()
                and not line.lstrip().startswith("#")
                and len(line) - len(line.lstrip()) <= indent
            ):
                end = j
                break
        return i + 1, end

    # At module scope, do not infer a flow into a later unrelated function.
    end = next(
        (i for i in range(index + 1, upper) if _PY_FUNCTION_RE.match(lines[i])),
        upper,
    )
    return lower, end


def _brace_depths(lines: list[str], lower: int, upper: int) -> list[int]:
    depth = 0
    depths = [0] * len(lines)
    for i in range(lower, upper):
        depths[i] = depth
        # This is intentionally lexical. Generated one-line code is excluded,
        # and braces in ordinary strings can only make us fail closed.
        depth += lines[i].count("{") - lines[i].count("}")
        depth = max(depth, 0)
    return depths


def _brace_scope(lines: list[str], index: int, lower: int, upper: int) -> tuple[int, int]:
    depths = _brace_depths(lines, lower, upper)
    target_depth = depths[index]
    for i in range(index - 1, lower - 1, -1):
        if not _BRACE_FUNCTION_RE.search(lines[i]) or "{" not in lines[i]:
            continue
        function_depth = depths[i]
        if target_depth <= function_depth:
            continue
        depth = function_depth
        for j in range(i, upper):
            depth += lines[j].count("{") - lines[j].count("}")
            if j >= index and depth <= function_depth:
                return i + 1, j
        return i + 1, upper

    # At top level, stop before the next function body.
    end = next(
        (
            i
            for i in range(index + 1, upper)
            if _BRACE_FUNCTION_RE.search(lines[i]) and "{" in lines[i]
        ),
        upper,
    )
    return lower, end


def _scope_bounds(lines: list[str], index: int, path: Path) -> tuple[int, int]:
    lower, upper = _fenced_bounds(lines, index) if path.name == "SKILL.md" else (0, len(lines))
    if path.suffix.lower() == ".py" or _PY_FUNCTION_RE.search("\n".join(lines[lower:upper])):
        return _python_scope(lines, index, lower, upper)
    return _brace_scope(lines, index, lower, upper)


def _clauses(text: str) -> list[str]:
    """Split independent one-line statements without splitting shell pipelines."""
    clauses: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    for index, character in enumerate(text):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if quote:
            if character == quote:
                quote = None
            continue
        if character in ("'", '"', "`"):
            quote = character
        elif character == ";":
            if clause := text[start:index].strip():
                clauses.append(clause)
            start = index + 1
    if clause := text[start:].strip():
        clauses.append(clause)
    return clauses


def _quote_at(text: str, position: int) -> str | None:
    """Return the active quote at an occurrence, if any."""
    quote: str | None = None
    escaped = False
    for character in text[:position]:
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if quote:
            if character == quote:
                quote = None
        elif character in ("'", '"', "`"):
            quote = character
    return quote


def _is_quoted(text: str, position: int) -> bool:
    return _quote_at(text, position) is not None


def _is_commented(text: str, position: int) -> bool:
    """Return whether ``position`` follows a line-comment marker."""
    line_start = text.rfind("\n", 0, position) + 1
    prefix = text[line_start:position]
    quote: str | None = None
    escaped = False
    for index, character in enumerate(prefix):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if quote:
            if character == quote:
                quote = None
            continue
        if character in ("'", '"', "`"):
            quote = character
            continue
        previous = prefix[index - 1] if index else " "
        if character == "#" and previous.isspace():
            return True
        if (
            character == "/"
            and index + 1 < len(prefix)
            and prefix[index + 1] == "/"
            and previous != ":"
        ):
            return True
    return False


def _unquoted_matches(pattern: re.Pattern[str], text: str) -> list[re.Match[str]]:
    return [
        match
        for match in pattern.finditer(text)
        if not _is_quoted(text, match.start()) and not _is_commented(text, match.start())
    ]


def _first_source_match(
    text: str,
    source_patterns: tuple[re.Pattern[str], ...],
    *,
    allow_shell_interpolation: bool = False,
    allow_quoted_source: bool = False,
) -> re.Match[str] | None:
    matches = [
        match
        for pattern in source_patterns
        for match in pattern.finditer(text)
        if not _is_commented(text, match.start())
        and (
            allow_quoted_source
            or not _is_quoted(text, match.start())
            or (
                allow_shell_interpolation
                and _quote_at(text, match.start()) == '"'
                and match.group(0).startswith("$")
            )
        )
    ]
    return min(matches, key=lambda match: match.start(), default=None)


def _source_is_inside_sink(
    clause: str,
    source_patterns: tuple[re.Pattern[str], ...],
    sink_pattern: re.Pattern[str],
    *,
    allow_shell_interpolation: bool = False,
    allow_quoted_source: bool = False,
) -> bool:
    """Return whether a source is lexically nested in a preceding sink call."""
    source = _first_source_match(
        clause,
        source_patterns,
        allow_shell_interpolation=allow_shell_interpolation,
        allow_quoted_source=allow_quoted_source,
    )
    if not source:
        return False
    source_pos = source.start()
    sink_matches = (
        [match for match in sink_pattern.finditer(clause) if match.start() < source_pos]
        if allow_quoted_source
        else [
            match
            for match in _unquoted_matches(sink_pattern, clause)
            if match.start() < source_pos
        ]
    )
    if not sink_matches:
        return False
    sink = sink_matches[-1]
    between = clause[sink.start() : source_pos]
    # Call-shaped sinks must have an opening delimiter that has not closed
    # before the source. Shell and PowerShell command sinks are deliberately
    # delimiter-free, but still require the value to follow the sink.
    if (
        allow_quoted_source or not _is_quoted(clause, source_pos)
    ) and between.count("(") > between.count(")"):
        return True
    if re.match(
        r"(?:curl\b|gog\s+gmail\s+send\b|sendmail\b|mail\s+-s\b)",
        sink.group(0).strip(),
        re.IGNORECASE,
    ):
        return True
    is_command_sink = sink.group(0).strip().lower() in {
        "eval",
        "exec",
        "iex",
        "invoke-expression",
    }
    return is_command_sink and bool(re.fullmatch(r"[\s('\"`]*", clause[sink.end() : source_pos]))


def _assigned_name(
    statement: str,
    source_patterns: tuple[re.Pattern[str], ...],
    *,
    allow_quoted_source: bool = False,
) -> str | None:
    if allow_quoted_source:
        sources = [
            match
            for pattern in source_patterns
            for match in pattern.finditer(statement)
            if not _is_commented(statement, match.start())
        ]
        source = min(sources, key=lambda match: match.start(), default=None)
    else:
        source = _first_source_match(statement, source_patterns)
    if not source:
        return None
    matches = [m for m in _ASSIGNMENT_RE.finditer(statement) if m.start() < source.start()]
    return matches[-1].group(1) if matches else None


def _name_re(name: str) -> re.Pattern[str]:
    flags = re.IGNORECASE if name.startswith("$") else 0
    return re.compile(
        rf"(?<![\w$])(?:\$?\{{?{re.escape(name)}\}}?)(?![\w$])",
        flags,
    )


def _assigns_name(clause: str, name: str) -> bool:
    """Return whether a clause overwrites the tracked value."""
    return any(match.group(1) == name for match in _ASSIGNMENT_RE.finditer(clause))


def statement_for_finding(
    skill: ParsedSkill,
    file_path: Path,
    line_number: int | None,
) -> str:
    """Return the bounded logical statement containing a finding.

    The result stays inside the Markdown fence or bundled source file selected
    by ``line_number``. Shell continuation lines and parenthesized calls are
    included, while unrelated neighboring examples are not.
    """
    content, line_base = _source_for_finding(skill, file_path, line_number)
    if not content or _is_generated_or_vendored(skill, file_path, content):
        return ""
    lines = _content_lines(skill, content)
    index = (line_number or line_base + 1) - line_base - 1
    if not 0 <= index < len(lines):
        return ""
    start, end = _statement_bounds(lines, index)
    return "\n".join(lines[start:end])


def scope_for_finding(
    skill: ParsedSkill,
    file_path: Path,
    line_number: int | None,
) -> str:
    """Return the lexical function or fenced scope containing a finding."""
    content, line_base = _source_for_finding(skill, file_path, line_number)
    if not content or _is_generated_or_vendored(skill, file_path, content):
        return ""
    lines = _content_lines(skill, content)
    index = (line_number or line_base + 1) - line_base - 1
    if not 0 <= index < len(lines):
        return ""
    start, end = _scope_bounds(lines, index, file_path)
    return "\n".join(lines[start:end])


def scope_from_finding(
    skill: ParsedSkill,
    file_path: Path,
    line_number: int | None,
) -> str:
    """Return the finding line through the end of its lexical scope.

    This preserves temporal ordering for conservative source-to-sink checks:
    a sink that ran before the source reference cannot be evidence that the
    source was transmitted.
    """
    content, line_base = _source_for_finding(skill, file_path, line_number)
    if not content or _is_generated_or_vendored(skill, file_path, content):
        return ""
    lines = _content_lines(skill, content)
    index = (line_number or line_base + 1) - line_base - 1
    if not 0 <= index < len(lines):
        return ""
    _start, end = _scope_bounds(lines, index, file_path)
    return "\n".join(lines[index:end])


def expression_reaches_sink(
    skill: ParsedSkill,
    file_path: Path,
    line_number: int | None,
    source_patterns: tuple[re.Pattern[str], ...],
    sink_pattern: re.Pattern[str],
    *,
    max_aliases: int = 8,
    allow_quoted_source: bool = False,
) -> bool:
    """Whether a source reaches a later sink through exact-name assignments.

    This is a deliberately small capability-flow primitive. It follows direct
    nesting and a bounded chain of local aliases in one lexical function. It
    does not infer callbacks, return values, properties, or cross-function
    flows. Reassignment kills a tracked name, and generated/vendored files are
    excluded because their lexical layout is not reliable evidence.
    """
    content, line_base = _source_for_finding(skill, file_path, line_number)
    if not content or _is_generated_or_vendored(skill, file_path, content):
        return False
    if file_path.suffix.lower() == ".py":
        content = _without_python_strings_and_comments(
            content,
            mask_strings=not allow_quoted_source,
        )
    elif file_path.suffix.lower() in {".cjs", ".js", ".mjs", ".ts"}:
        content = _without_c_block_comments(content)
    lines = content.splitlines()
    index = (line_number or line_base + 1) - line_base - 1
    if not 0 <= index < len(lines):
        return False

    stmt_start, stmt_end = _statement_bounds(lines, index)
    statement = "\n".join(lines[stmt_start:stmt_end])
    clauses = _clauses(statement)

    for clause in clauses:
        if _source_is_inside_sink(
            clause,
            source_patterns,
            sink_pattern,
            allow_quoted_source=allow_quoted_source,
        ):
            return True

    source_name = _assigned_name(
        statement,
        source_patterns,
        allow_quoted_source=allow_quoted_source,
    )
    if not source_name:
        return False

    _scope_start, scope_end = _scope_bounds(lines, index, file_path)
    tracked = {source_name}
    source_clause_index = next(
        (
            i
            for i, clause in enumerate(clauses)
            if _first_source_match(
                clause,
                source_patterns,
                allow_quoted_source=allow_quoted_source,
            )
        ),
        len(clauses) - 1,
    )
    candidates = clauses[source_clause_index + 1 :]
    cursor = stmt_end
    while cursor < scope_end:
        candidate_start, candidate_end = _statement_bounds(lines, cursor)
        candidate_end = min(candidate_end, scope_end)
        candidates.extend(_clauses("\n".join(lines[candidate_start:candidate_end])))
        cursor = max(candidate_end, cursor + 1)

    for clause in candidates:
        previously_tracked = set(tracked)
        assignment = next(iter(_ASSIGNMENT_RE.finditer(clause)), None)
        value_text = clause[assignment.end() :] if assignment else clause
        used_names = {
            name
            for name in previously_tracked
            if _first_source_match(
                value_text,
                (_name_re(name),),
                allow_shell_interpolation=True,
                allow_quoted_source=allow_quoted_source,
            )
        }
        if used_names and _unquoted_matches(sink_pattern, clause):
            return True

        for name in previously_tracked:
            if _assigns_name(clause, name) and name not in used_names:
                tracked.remove(name)
        if assignment and used_names and assignment.group(1) not in tracked:
            if len(tracked) >= max_aliases:
                return False
            tracked.add(assignment.group(1))
        if not tracked:
            return False
    return False


def expression_reaches_execution(
    skill: ParsedSkill,
    file_path: Path,
    line_number: int | None,
    source_patterns: tuple[re.Pattern[str], ...],
    sink_pattern: re.Pattern[str] = EXECUTION_SINK_RE,
) -> bool:
    """Whether a source expression directly or by assignment reaches a sink."""
    content, line_base = _source_for_finding(skill, file_path, line_number)
    if not content or _is_generated_or_vendored(skill, file_path, content):
        return False
    if file_path.suffix.lower() == ".py":
        content = _without_python_strings_and_comments(content)
    elif file_path.suffix.lower() in {".cjs", ".js", ".mjs", ".ts"}:
        content = _without_c_block_comments(content)
    lines = content.splitlines()
    index = (line_number or line_base + 1) - line_base - 1
    if not 0 <= index < len(lines):
        return False

    stmt_start, stmt_end = _statement_bounds(lines, index)
    statement = "\n".join(lines[stmt_start:stmt_end])
    # Backticks and quotes in SKILL.md are presentation syntax around commands,
    # not runtime string literals. Treat a source expression inside them as
    # executable instruction text while retaining quote masking for scripts.
    allow_quoted_source = file_path.name == "SKILL.md"

    clauses = _clauses(statement)

    # A source nested in an execution call, including a shell pipeline, is a
    # direct flow. Mere co-occurrence within the same statement is not.
    for clause in clauses:
        source_match = _first_source_match(
            clause,
            source_patterns,
            allow_quoted_source=allow_quoted_source,
        )
        if source_match and (
            _source_is_inside_sink(
                clause,
                source_patterns,
                sink_pattern,
                allow_quoted_source=allow_quoted_source,
            )
            or _PIPE_SHELL_RE.search(clause[source_match.start() :])
        ):
            return True

    name = _assigned_name(
        statement,
        source_patterns,
        allow_quoted_source=allow_quoted_source,
    )
    if not name:
        return False

    _scope_start, scope_end = _scope_bounds(lines, index, file_path)
    name_pattern = _name_re(name)
    source_clause_index = next(
        (
            i
            for i, clause in enumerate(clauses)
            if _first_source_match(
                clause,
                source_patterns,
                allow_quoted_source=allow_quoted_source,
            )
        ),
        len(clauses) - 1,
    )
    candidates = clauses[source_clause_index + 1 :]
    candidates.extend(
        clause for candidate in lines[stmt_end:scope_end] for clause in _clauses(candidate)
    )
    for clause in candidates:
        if _assigns_name(clause, name):
            return False
        name_match = _first_source_match(
            clause,
            (name_pattern,),
            allow_shell_interpolation=True,
        )
        if name_match and (
            _source_is_inside_sink(
                clause,
                (name_pattern,),
                sink_pattern,
                allow_shell_interpolation=True,
            )
            or _PIPE_SHELL_RE.search(clause[name_match.start() :])
        ):
            return True
    return False


def literal_reaches_decode_and_execution(
    skill: ParsedSkill,
    file_path: Path,
    line_number: int | None,
    decode_patterns: tuple[re.Pattern[str], ...],
) -> bool:
    """Whether an encoded literal is decoded and the result reaches execution."""
    content, line_base = _source_for_finding(skill, file_path, line_number)
    if not content or _is_generated_or_vendored(skill, file_path, content):
        return False
    if file_path.suffix.lower() == ".py":
        literal_content = _without_python_strings_and_comments(content, mask_strings=False)
    elif file_path.suffix.lower() in {".cjs", ".js", ".mjs", ".ts"}:
        literal_content = _without_c_block_comments(content)
    else:
        literal_content = content
    lines = literal_content.splitlines()
    code_lines = (
        _without_python_strings_and_comments(content).splitlines()
        if file_path.suffix.lower() == ".py"
        else lines
    )
    index = (line_number or line_base + 1) - line_base - 1
    if not 0 <= index < len(lines):
        return False

    stmt_start, stmt_end = _statement_bounds(lines, index)
    statement = "\n".join(lines[stmt_start:stmt_end])
    if any(pattern.search(statement) for pattern in decode_patterns):
        return expression_reaches_execution(
            skill,
            file_path,
            line_number,
            decode_patterns,
        )

    literal_name = _assigned_name(
        statement,
        (re.compile(r"[A-Za-z0-9+/]{24,}={0,2}"),),
        allow_quoted_source=True,
    )
    if not literal_name:
        return False

    _scope_start, scope_end = _scope_bounds(code_lines, index, file_path)
    literal_pattern = _name_re(literal_name)
    for decode_index in range(stmt_end, scope_end):
        candidate = code_lines[decode_index]
        if _assigns_name(candidate, literal_name):
            return False
        literal_match = _first_source_match(
            candidate,
            (literal_pattern,),
            allow_shell_interpolation=True,
        )
        if literal_match and any(p.search(candidate) for p in decode_patterns):
            return expression_reaches_execution(
                skill,
                file_path,
                decode_index + line_base + 1,
                decode_patterns,
            )
    return False
