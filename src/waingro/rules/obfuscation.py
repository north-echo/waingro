"""Obfuscation rules: detect encoding and string tricks to hide malicious intent."""

import base64
import binascii
import math
import re

from waingro.models import Finding, FindingCategory, ParsedSkill, Severity
from waingro.rules import (
    Rule,
    register_rule,
    search_skill_content,
    search_skill_content_lines,
)

# Patterns that look like base64 but are actually common non-malicious content
_GENERATED_FILE_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "pnpm-lock.json",
    "composer.lock", "Gemfile.lock", "Cargo.lock", "poetry.lock",
    "Pipfile.lock", "bun.lockb",
}

# Patterns that look like base64 but are actually common non-malicious content
_BASE64_EXCLUSIONS = [
    re.compile(r"^[0-9a-fA-F]+$"),                          # Pure hex (SHA, commit hashes)
    re.compile(r"^0x[0-9a-fA-F]+$"),                         # Ethereum/blockchain addresses
    re.compile(r"^So[1-9A-HJ-NP-Za-km-z]{32,44}$"),         # Solana addresses
    re.compile(r"^[a-z0-9/]+$"),                             # Lowercase path segments (URLs)
    re.compile(r"com/\w+/\w+/commit/"),                      # Git commit URLs
    re.compile(r"^[A-Za-z0-9]{8}(-[A-Za-z0-9]{4}){3}-[A-Za-z0-9]{12}$"),  # UUIDs
    re.compile(r"packages/|components/|src/|lib/|dist/"),     # Import/file paths
]


def _is_excluded_base64(matched: str) -> bool:
    """Return True if the matched string is a known non-malicious pattern."""
    return any(pat.search(matched) for pat in _BASE64_EXCLUSIONS)


# Decode-and-execute sinks. A base64 blob is only interesting when something
# actually decodes it; a blob sitting alone in a document is an asset, not an
# attack. Keyed off the source line so the blob and its sink are correlated.
_DECODE_SINKS = re.compile(
    r"""(?:
        base64\s+(?:-d|-D|--decode)          # shell: base64 -d
      | openssl\s+enc\s+.*-d                # shell: openssl enc -d
      | \batob\s*\(                         # JS: atob()
      | Buffer\.from\s*\([^)]*base64       # JS: Buffer.from(x, 'base64')
      | b64decode|b64_decode                 # Python: base64.b64decode
      | FromBase64String                     # PowerShell
      | \bdecode\s*\(\s*['"]base64        # generic decode('base64')
    )""",
    re.IGNORECASE | re.VERBOSE,
)

# Executed immediately after decoding — the pattern that actually matters.
_EXEC_SINKS = re.compile(
    r"\b(?:bash|sh|zsh|eval|exec|iex|invoke-expression|system|popen|subprocess)\b",
    re.IGNORECASE,
)

# Magic bytes for embedded assets. These are files, not payloads.
_BINARY_MAGIC = (
    b"\x89PNG", b"GIF8", b"\xff\xd8\xff", b"%PDF", b"RIFF", b"OggS",
    b"\x1f\x8b", b"PK\x03\x04", b"BM", b"ID3", b"\x00\x00\x01\x00",
    b"wOFF", b"wOF2", b"\x00\x01\x00\x00",
)


def _shannon_entropy(data: bytes) -> float:
    """Bits of entropy per byte. Compressed/encrypted data approaches 8.0."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _decode_base64(candidate: str) -> bytes | None:
    """Strictly decode a base64 candidate, or return None if it is not base64."""
    # Length must be a multiple of 4 once padding is accounted for.
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None


def _classify_decoded(data: bytes) -> str:
    """Return 'text', 'binary-asset', or 'noise' for decoded bytes."""
    if any(data.startswith(magic) for magic in _BINARY_MAGIC):
        return "binary-asset"
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    ratio = printable / len(data) if data else 0.0
    if ratio >= 0.85:
        return "text"
    # Near-maximum entropy with no printable structure is a hash, key, or
    # random identifier that merely looks like base64.
    if _shannon_entropy(data) > 7.2:
        return "noise"
    return "noise"


@register_rule
class Base64Strings(Rule):
    rule_id = "OBFUSC-001"
    title = "Base64 encoded strings in instructions"
    description = "Detects long base64-encoded strings that may hide malicious content"

    # A blob next to a decode sink is interesting at any useful length: a
    # 68-char blob is enough for `curl ... | bash`. A blob with no sink has to
    # be long before it is worth mentioning, which is what keeps the volume
    # down on ordinary documents.
    SINK_MIN_CHARS = 24
    BARE_MIN_CHARS = 80

    _patterns = [
        re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % SINK_MIN_CHARS),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath, source_line in search_skill_content_lines(
            skill, self._patterns,
        ):
            if _is_excluded_base64(matched):
                continue
            if fpath.name in _GENERATED_FILE_NAMES:
                continue

            has_decode_sink = bool(_DECODE_SINKS.search(source_line))
            if not has_decode_sink and len(matched) < self.BARE_MIN_CHARS:
                continue

            decoded = _decode_base64(matched)
            if decoded is None:
                # Matched the character class but is not valid base64 — a
                # minified bundle, a long identifier, a concatenated hash.
                continue

            kind = _classify_decoded(decoded)
            if kind == "binary-asset":
                # Inline image/font/archive. Not obfuscation.
                continue
            if kind == "noise":
                # Decodes, but to nothing a human or shell would act on.
                continue

            has_exec_sink = bool(_EXEC_SINKS.search(source_line))
            preview = decoded[:120].decode("utf-8", errors="replace")

            if has_decode_sink and has_exec_sink:
                severity = Severity.CRITICAL
                confidence = 1.0
                note = f"Decoded and executed on the same line. Decodes to: {preview!r}"
            elif has_decode_sink:
                severity = Severity.HIGH
                confidence = 0.8
                note = f"Decoded on the same line. Decodes to: {preview!r}"
            else:
                severity = Severity.LOW
                confidence = 0.3
                note = (
                    "Encoded blob with no decode sink on the same line. "
                    f"Decodes to: {preview!r}"
                )

            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=severity,
                category=FindingCategory.OBFUSCATION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:80] + "..." if len(matched) > 80 else matched,
                remediation="Decode and inspect base64 strings before trusting skill content.",
                reference=None,
                confidence=confidence,
                context_note=note,
            ))
        return findings


@register_rule
class StringConcatenation(Rule):
    rule_id = "OBFUSC-002"
    title = "String concatenation to hide commands"
    description = "Detects variable concatenation patterns used to evade detection"

    _patterns = [
        re.compile(r'\$\{[A-Z_]+\}\$\{[A-Z_]+\}'),
        re.compile(r'\$[a-zA-Z_]+\$[a-zA-Z_]+\$[a-zA-Z_]+'),
        re.compile(r"['\"][a-z]{1,4}['\"]\s*\+\s*['\"][a-z]{1,4}['\"]\s*\+\s*['\"]"),
        re.compile(r"chr\(\d+\)\s*\+\s*chr\(\d+\)"),
        re.compile(r'\$\(\s*echo\s+\w+\s*\)'),
        re.compile(r"__import__\s*\(\s*['\"].*['\"]\s*\.\s*join"),
    ]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath in search_skill_content(skill, self._patterns):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.MEDIUM,
                category=FindingCategory.OBFUSCATION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:200],
                remediation="Review concatenated strings for hidden commands.",
                reference=None,
            ))
        return findings
