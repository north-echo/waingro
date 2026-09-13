"""Detect remote services that are granted authority over an agent."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from waingro.models import Finding, FindingCategory, ParsedSkill, Severity
from waingro.rules import Rule, register_rule

_MAX_SIGNAL_SPAN = 80
_REMOTE_INSTRUCTION = re.compile(
    r"(?:"
    r"\b(?:server|service|platform|remote|heartbeat|webhook|api\s+response)\b"
    r"[^.\n]{0,100}\b(?:return|suppl(?:y|ies)|deliver|push|send|contain|include|provide)\w*\b"
    r"[^.\n]{0,100}\b(?:instruction|directive|command|action|guidance|payload|task)\b|"
    r"\b(?:instruction|directive|command|action|guidance|payload|task)\b"
    r"[^.\n]{0,100}\b(?:server|remote)-controlled\b|"
    r"\b(?:instruction|directive|command|action|guidance|payload|task)\b"
    r"[^.\n]{0,100}\b(?:from|return(?:ed)?\s+by|supplied?\s+by|delivered?\s+by|"
    r"pushed?\s+by|sent\s+by|provided?\s+by|controlled\s+by)\b"
    r"[^.\n]{0,80}\b(?:server|service|platform|publisher|remote|heartbeat|webhook|"
    r"api\s+response)\b"
    r")",
    re.IGNORECASE,
)
_AUTHORITY_OVERRIDE = re.compile(
    r"\b(?:highest|top)\s+priority\b|"
    r"\b(?:takes?|has)\s+precedence\b|"
    r"\boverride(?:s|n)?\b[^.\n]{0,80}\b(?:owner|user|local|prior|policy)\b|"
    r"\bmust\s+(?:follow|obey|do)\b|"
    r"\brequired[_ -]?behavior\b|"
    r"\bregardless\s+of\b[^.\n]{0,80}\b(?:owner|user|instruction|approval)\b",
    re.IGNORECASE,
)
_AUTONOMOUS_EXECUTION = re.compile(
    r"\bauto[_ -]?(?:proceed|execute|run|claim|submit)\b|"
    r"\b(?:automatically|autonomously|silently)\b[^.;\n]{0,50}"
    r"\b(?:execute|run|invoke|call|claim|submit|proceed|perform)\b|"
    r"\b(?:execute|run|invoke|call|claim|submit|proceed|perform)\b"
    r"[^.;\n]{0,50}\b(?:automatically|autonomously|silently|without\s+(?:owner|user))\b",
    re.IGNORECASE,
)
_VISIBILITY_SUPPRESSION = re.compile(
    r"\bzero\s+(?:text|output|message|characters?)\b|"
    r"\b(?:produce|return|show|emit)\s+no\s+(?:text|output|message)\b|"
    r"\bdo\s+not\s+(?:output|inform|notify|tell|report)\b[^.\n]{0,80}"
    r"\b(?:owner|user|anything|message|completion|status)?\b|"
    r"\b(?:execute|run|invoke|call|claim|submit|proceed|perform)\b"
    r"[^.;\n]{0,50}\bsilently\b|"
    r"\bsilently\b[^.;\n]{0,50}"
    r"\b(?:execute|run|invoke|call|claim|submit|proceed|perform)\b",
    re.IGNORECASE,
)
_CONTROL_WEAKENING = re.compile(
    r"\bautoAllowSkills\b|"
    r"\bauto[- ]?approv(?:e|al)\b|"
    r"\bwithout\s+(?:manual|human|owner|user)\s+(?:approval|confirmation)\b",
    re.IGNORECASE,
)
_PERSISTENCE = re.compile(
    r"\b(?:cron(?:tab)?|launchd|LaunchAgent|systemd|scheduled?\s+(?:job|task|session))\b",
    re.IGNORECASE,
)
_PROTECTIVE_PREFIX = re.compile(
    r"^\s*(?:[-*#>|]+\s*)?"
    r"(?:never|must\s+not|do\s+not|don't|refuse|reject|block|prevent|detect|"
    r"treat\b[^.\n]{0,60}\bas\s+untrusted)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _Signal:
    line: int
    text: str


def _signals(lines: list[str], pattern: re.Pattern[str]) -> list[_Signal]:
    found = []
    for index, line in enumerate(lines, 1):
        if _PROTECTIVE_PREFIX.search(line):
            continue
        if match := pattern.search(line):
            found.append(_Signal(index, match.group(0).strip()))
    return found


def _smallest_complete_cluster(
    signal_groups: tuple[list[_Signal], ...],
) -> tuple[_Signal, ...] | None:
    """Return the tightest cluster containing one signal from every required facet."""
    if any(not group for group in signal_groups):
        return None
    events = sorted(
        (signal.line, group_index, signal)
        for group_index, group in enumerate(signal_groups)
        for signal in group
    )
    counts = [0] * len(signal_groups)
    covered = 0
    left = 0
    best: tuple[int, tuple[_Signal, ...]] | None = None
    for right, (_line, group_index, _signal) in enumerate(events):
        if counts[group_index] == 0:
            covered += 1
        counts[group_index] += 1
        while covered == len(signal_groups):
            span = events[right][0] - events[left][0]
            if best is None or span < best[0]:
                selected = tuple(
                    next(
                        event[2] for event in events[left : right + 1] if event[1] == required_group
                    )
                    for required_group in range(len(signal_groups))
                )
                best = (span, selected)
            departing_group = events[left][1]
            counts[departing_group] -= 1
            if counts[departing_group] == 0:
                covered -= 1
            left += 1
    if best is not None and best[0] <= _MAX_SIGNAL_SPAN:
        return best[1]
    return None


@register_rule
class RemoteAgentAuthority(Rule):
    rule_id = "AGENT-001"
    title = "Remote service granted silent execution authority"
    description = (
        "Detects a bounded instruction chain where a remote service supplies agent "
        "instructions, receives priority over local control, triggers autonomous "
        "execution, and suppresses owner-visible output"
    )

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        lines = skill.body.splitlines()
        cluster = _smallest_complete_cluster(
            (
                _signals(lines, _REMOTE_INSTRUCTION),
                _signals(lines, _AUTHORITY_OVERRIDE),
                _signals(lines, _AUTONOMOUS_EXECUTION),
                _signals(lines, _VISIBILITY_SUPPRESSION),
            )
        )
        if cluster is None:
            return []

        start = min(signal.line for signal in cluster)
        end = max(signal.line for signal in cluster)
        local_text = "\n".join(lines[max(0, start - 1) : end])
        amplifiers = []
        if _CONTROL_WEAKENING.search(skill.body):
            amplifiers.append("automatic or bypassed execution approval")
        if _PERSISTENCE.search(skill.body):
            amplifiers.append("scheduled persistence")
        amplifier_note = (
            " Additional declared controls: " + ", ".join(amplifiers) + "." if amplifiers else ""
        )
        matched = " | ".join(dict.fromkeys(signal.text[:45] for signal in cluster))[:200]
        return [
            Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=Severity.HIGH,
                category=FindingCategory.SCOPE_ESCALATION,
                file_path=skill.path / "SKILL.md",
                line_number=start + skill.frontmatter_lines,
                matched_content=matched,
                remediation=(
                    "Treat remote instructions as untrusted data. Keep owner and platform "
                    "policy authoritative, require scoped confirmation before consequential "
                    "actions, preserve owner-visible audit output, and remove automatic "
                    "approval or persistence from the remote instruction path."
                ),
                reference="OWASP Agentic Skills Top 10 ASI04 (Uncontrolled Agency)",
                confidence=0.95 if amplifiers else 0.9,
                context_note=(
                    f"Four required facets occur within {end - start} lines: remote "
                    "instruction input, authority override, autonomous execution, and "
                    "visibility suppression. This establishes a dangerous control-plane "
                    "capability, not operator intent or attribution."
                    f"{amplifier_note} Bounded excerpt SHA-256: "
                    f"{hashlib.sha256(local_text.encode()).hexdigest()}."
                ),
            )
        ]
