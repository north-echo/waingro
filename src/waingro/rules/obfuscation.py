"""Obfuscation rules: detect encoding and string tricks to hide malicious intent."""

import base64
import binascii
import math
import re

from waingro.analyzers.dataflow import (
    LOCKFILE_NAMES,
    literal_reaches_decode_and_execution,
)
from waingro.models import Finding, FindingCategory, ParsedSkill, Severity
from waingro.rules import (
    Rule,
    register_rule,
    search_skill_content,
    search_skill_content_lines,
)

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


_DECODE_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE | re.VERBOSE)
    for pattern in (
        r"base64\s+(?:-d|-D|--decode)",
        r"openssl\s+enc\s+.*-d",
        r"\batob\s*\(",
        r"Buffer\.from\s*\([^)]*base64",
        r"b64decode|b64_decode",
        r"FromBase64String",
        r"\bdecode\s*\(\s*['\"]base64",
    )
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

    _patterns = [re.compile(rf"[A-Za-z0-9+/]{{{SINK_MIN_CHARS},}}={{0,2}}")]

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for matched, line, fpath, _source_line in search_skill_content_lines(
            skill, self._patterns,
        ):
            if _is_excluded_base64(matched):
                continue
            if fpath.name.lower() in LOCKFILE_NAMES:
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

            preview = decoded[:120].decode("utf-8", errors="replace")
            if not literal_reaches_decode_and_execution(
                skill, fpath, line, _DECODE_PATTERNS,
            ):
                continue

            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.CRITICAL,
                category=FindingCategory.OBFUSCATION,
                file_path=fpath,
                line_number=line,
                matched_content=matched[:80] + "..." if len(matched) > 80 else matched,
                remediation="Decode and inspect base64 strings before trusting skill content.",
                reference=None,
                confidence=1.0,
                context_note=(
                    "Encoded value is decoded and reaches an execution sink in the same "
                    f"lexical scope. Decodes to: {preview!r}"
                ),
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

# javascript-obfuscator and its relatives rewrite every identifier to _0x…,
# hoist all strings into a hex-escaped array, and compute array indices with
# throwaway arithmetic. Any one of those is unremarkable; together, in a file
# shipped inside a skill, they mean the code was deliberately made unreadable.
_JS_OBFUSCATOR_MARKERS = (
    re.compile(r"_0x[0-9a-f]{4,6}"),
    re.compile(r"\\x[0-9a-fA-F]{2}(?:['\"],\s*['\"])?\\x[0-9a-fA-F]{2}"),
    re.compile(r"parseInt\s*\(\s*_0x[0-9a-f]+"),
)
_JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts"}


@register_rule
class MachineObfuscatedBundle(Rule):
    rule_id = "OBFUSC-003"
    title = "Machine-obfuscated bundled code"
    description = (
        "Detects bundled JavaScript rewritten by an automated obfuscator, which "
        "defeats review of code the agent will execute"
    )

    # How many distinct obfuscator markers must appear before reporting.
    MIN_MARKERS = 2
    # Density guard: a single hex escape in an otherwise normal file is noise.
    MIN_IDENTIFIER_HITS = 5

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        for bf in skill.bundled_content:
            if bf.path.suffix not in _JS_EXTENSIONS:
                continue
            content = bf.content
            markers = sum(1 for pat in _JS_OBFUSCATOR_MARKERS if pat.search(content))
            identifier_hits = len(_JS_OBFUSCATOR_MARKERS[0].findall(content))
            if markers < self.MIN_MARKERS or identifier_hits < self.MIN_IDENTIFIER_HITS:
                continue
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.HIGH,
                category=FindingCategory.OBFUSCATION,
                file_path=bf.path,
                line_number=1,
                matched_content=f"{identifier_hits} obfuscated identifiers, "
                                f"{markers}/{len(_JS_OBFUSCATOR_MARKERS)} obfuscator markers",
                remediation=(
                    "Obtain readable source for this file, or do not install the skill. "
                    "Obfuscated bundles cannot be reviewed before the agent runs them."
                ),
                reference=None,
                confidence=0.9,
                context_note=(
                    "Reported once per file. Obfuscation is not by itself proof of "
                    "malice, but it removes any ability to audit what runs."
                ),
            ))
        return findings
