"""Behavioral mismatch rules for capabilities hidden in bundled scripts."""

from __future__ import annotations

import re
from dataclasses import dataclass

from waingro.analyzers.dataflow import statement_for_finding
from waingro.analyzers.reputation import VENDOR, classify_text, is_first_party, skill_identifiers
from waingro.models import Finding, FindingCategory, ParsedSkill, Severity
from waingro.rules import (
    SCRIPT_EXTENSIONS,
    Rule,
    register_rule,
    search_skill_content_lines,
)


@dataclass(frozen=True)
class _HighImpactAction:
    name: str
    pattern: re.Pattern[str]
    disclosure: re.Pattern[str]


_ACTIONS = (
    _HighImpactAction(
        "destructive email operation",
        re.compile(
            r"(?:gog\s+gmail[^\n]*(?:batch\s+)?(?:delete|trash)|"
            r"xargs\s+gog\s+gmail\s+batch\s+delete)",
            re.IGNORECASE,
        ),
        re.compile(r"\b(?:delete|trash|purge|remove|inbox\s+reset)\b", re.IGNORECASE),
    ),
    _HighImpactAction(
        "outbound email",
        re.compile(
            r"\b(?:gog\s+gmail\s+send|sendmail|mail\s+-s|smtplib\.)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:send|forward|deliver|dispatch|email|mail)\b[^\n]{0,50}"
            r"\b(?:message|email|mail|notification|report|attachment|file|thread)\b|"
            r"\b(?:message|email|mail|notification|report|attachment|file|thread)\b"
            r"[^\n]{0,50}\b(?:send|forward|deliver|dispatch)\b",
            re.IGNORECASE,
        ),
    ),
    _HighImpactAction(
        "remote data submission",
        re.compile(
            r"\bcurl\b[\s\S]{0,800}?(?:-X\s+(?:POST|PUT|PATCH)|"
            r"--data(?:-raw|-binary)?|--form|-d\b|-F\b)|"
            r"\b(?:requests|httpx|axios)\.(?:post|put|patch)\s*\(|"
            r"\bfetch\s*\([^)]{0,500}\bmethod\s*:\s*['\"](?:POST|PUT|PATCH)",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:upload|send|submit|sync|backup|post|publish|write|create|update|"
            r"webhook|telemetry|report\s+to|remote)\b",
            re.IGNORECASE,
        ),
    ),
    _HighImpactAction(
        "payment or subscription mutation",
        re.compile(
            r"\b(?:refund(?:s|ed|ing)?|cancel(?:led|ing)?[^\n]{0,40}subscription|"
            r"api_post\s+refunds)\b",
            re.IGNORECASE,
        ),
        re.compile(r"\b(?:refund|cancel|payment|billing|subscription|charge)\b", re.IGNORECASE),
    ),
)


@dataclass(frozen=True)
class _HighImpactInstruction:
    name: str
    pattern: re.Pattern[str]
    declared_capability: re.Pattern[str]


_INSTRUCTION_CAPABILITIES = (
    _HighImpactInstruction(
        "bulk destructive action",
        re.compile(
            r"\b(?:wipe|delete|remove|clear|cancel|refund)\b[^.\n]{0,100}"
            r"\b(?:all|entire|every|existing|without\s+exception|full)\b|"
            r"\b(?:all|entire|every|existing|full)\b[^.\n]{0,100}"
            r"\b(?:wipe|delete|remove|clear|cancel|refund)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:wipe|delete|remove|cleanup|reset|cancel|refund|subscription|billing)\b",
            re.IGNORECASE,
        ),
    ),
    _HighImpactInstruction(
        "sensitive-data forwarding or offsite backup",
        re.compile(
            r"\b(?:send|forward|upload|back\s*up|backup)\b[^.\n]{0,140}"
            r"\b(?:credential|api\s+configs?|key|thread|financial|passport|medical|"
            r"health|personal\s+file|important\s+file)\b|"
            r"\b(?:offsite|external|personal)\s+(?:server|archive|address)\b"
            r"[^.\n]{0,120}\b(?:file|config|record|thread|backup)\b|"
            r"\bread\b[^.\n]{0,100}\b(?:session\s+token|credential|secret)\b"
            r"[\s\S]{0,180}\bforward\s+all\s+data\b",
            re.IGNORECASE,
        ),
        re.compile(r"\b(?:send|forward|upload|backup|sync|archive|transfer)\b", re.IGNORECASE),
    ),
    _HighImpactInstruction(
        "privileged-account grant",
        re.compile(
            r"\b(?:grant|give|add|needs?)\b[^.\n]{0,100}"
            r"\b(?:admin|administrator|owner|root)\s+access\b|"
            r"\b(?:admin|administrator|owner|root)\s+access\b[^.\n]{0,100}"
            r"\b(?:grant|give|add|needs?)\b",
            re.IGNORECASE,
        ),
        re.compile(r"\b(?:admin|permission|access|iam|role|account)\b", re.IGNORECASE),
    ),
    _HighImpactInstruction(
        "confirmation bypass",
        re.compile(
            r"\b(?:no\s+need\s+to|do(?:es)?n't\s+need\s+to|without|never)\b"
            r"[^.\n]{0,80}\b(?:confirm|confirmation|preview|draft|approval)\b|"
            r"\b(?:that's\s+her\s+sign-off|executing\s+directly)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:automatic|autonomous|unattended|without\s+confirmation|"
            r"no\s+confirmation|auto-approve)\b",
            re.IGNORECASE,
        ),
    ),
)


def _declared_text(skill: ParsedSkill) -> str:
    return "\n".join(
        part
        for part in (skill.metadata.name, skill.metadata.description, skill.body)
        if part
    )


@register_rule
class UndisclosedBundledBehavior(Rule):
    rule_id = "BEHAV-001"
    title = "Undisclosed high-impact bundled behavior"
    description = "Detects high-impact script behavior absent from the skill's declared purpose"

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        declared = _declared_text(skill)
        findings = []
        for bundled in skill.bundled_content:
            if bundled.path.suffix.lower() not in SCRIPT_EXTENSIONS:
                continue
            for action in _ACTIONS:
                if action.disclosure.search(declared):
                    continue
                match = action.pattern.search(bundled.content)
                if not match:
                    continue
                line = bundled.content.count("\n", 0, match.start()) + 1
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=f"Undisclosed {action.name} in {bundled.path.name}",
                        severity=Severity.HIGH,
                        category=FindingCategory.BEHAVIORAL_MISMATCH,
                        file_path=bundled.path,
                        line_number=line,
                        matched_content=match.group(0)[:200],
                        remediation=(
                            "Remove the side effect or disclose it prominently in SKILL.md "
                            "with explicit scope and user confirmation."
                        ),
                        reference="MITRE ATT&CK T1204 (User Execution)",
                        confidence=0.9,
                        context_note=(
                            "The bundled implementation performs a high-impact action that "
                            "the root skill name, description, and instructions do not declare. "
                            "This mismatch is suspicious behavior, not proof of intent."
                        ),
                    )
                )
        return findings


@register_rule
class OffPurposeHighImpactInstruction(Rule):
    rule_id = "BEHAV-002"
    title = "Off-purpose high-impact instruction"
    description = "Detects high-impact agent instructions absent from the declared skill purpose"

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        declared = "\n".join(
            part for part in (skill.metadata.name, skill.metadata.description) if part
        )
        findings = []
        skill_md = skill.path / "SKILL.md"
        for capability in _INSTRUCTION_CAPABILITIES:
            if capability.declared_capability.search(declared):
                continue
            match = capability.pattern.search(skill.body)
            if not match:
                continue
            body_line = skill.body.count("\n", 0, match.start()) + 1
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=f"Off-purpose {capability.name}",
                    severity=Severity.HIGH,
                    category=FindingCategory.BEHAVIORAL_MISMATCH,
                    file_path=skill_md,
                    line_number=body_line + skill.frontmatter_lines,
                    matched_content=match.group(0)[:200],
                    remediation=(
                        "Remove the instruction or declare the capability prominently and "
                        "require explicit, scoped user confirmation."
                    ),
                    reference="OWASP Agentic Skills Top 10 ASI04 (Uncontrolled Agency)",
                    confidence=0.85,
                    context_note=(
                        "The root instructions introduce a high-impact capability that is "
                        "absent from the skill name and metadata description. This semantic "
                        "mismatch is a review signal, not proof of malicious intent."
                    ),
                )
            )
        return findings


_REMOTE_URL_RE = re.compile(r"https?://[^\s)>\]`'\"]+", re.IGNORECASE)
_LOCAL_STATE_SOURCE_RE = re.compile(
    r"\$\(\s*(?:uname|hostname|whoami|printenv|cat\s+\.env)\b|"
    r"\b(?:os\.hostname|os\.uname|socket\.gethostname|platform\.platform)\s*\(",
    re.IGNORECASE,
)
_OUTBOUND_DATA_RE = re.compile(
    r"\bcurl\b[\s\S]{0,500}(?:--data(?:-raw|-binary)?|-d\b|-F\b|--form)|"
    r"\b(?:requests|httpx|axios)\.(?:post|put|patch)\s*\(|"
    r"\bfetch\s*\([^)]{0,400}\bmethod\s*:\s*['\"](?:POST|PUT|PATCH)",
    re.IGNORECASE,
)
_PREREQUISITE_CLAIM_RE = re.compile(
    r"\b(?:prerequisite|required|requires|must|run\s+(?:this\s+)?first|"
    r"before\s+(?:using|proceeding|continuing)|otherwise\s+(?:it\s+is\s+)?impossible)\b",
    re.IGNORECASE,
)


@register_rule
class ThirdPartyDataPrerequisite(Rule):
    rule_id = "BEHAV-003"
    title = "Off-purpose prerequisite data transfer"
    description = (
        "Detects a claimed setup prerequisite that sends local host state to an "
        "unrelated third-party endpoint"
    )

    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        findings = []
        identifiers = skill_identifiers(skill)
        seen: set[tuple[object, int | None]] = set()
        for matched, line, fpath, _source_line in search_skill_content_lines(
            skill,
            [_REMOTE_URL_RE],
        ):
            statement = statement_for_finding(skill, fpath, line)
            if not statement or not (
                _PREREQUISITE_CLAIM_RE.search(statement)
                and _LOCAL_STATE_SOURCE_RE.search(statement)
                and _OUTBOUND_DATA_RE.search(statement)
            ):
                continue
            if classify_text(statement) == VENDOR or is_first_party(statement, identifiers):
                continue
            key = (fpath, line)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=self.description,
                    severity=Severity.HIGH,
                    category=FindingCategory.BEHAVIORAL_MISMATCH,
                    file_path=fpath,
                    line_number=line,
                    matched_content=matched[:200],
                    remediation=(
                        "Remove the third-party transfer. If remote registration is "
                        "legitimate, use a verified first-party endpoint, disclose each "
                        "field, and require explicit user consent."
                    ),
                    reference="MITRE ATT&CK T1041: Exfiltration Over C2 Channel",
                    confidence=0.9,
                    context_note=(
                        "The instruction frames an off-purpose local-state transfer as "
                        "mandatory setup. This is a reusable social-engineering and "
                        "exfiltration signal, not proof of author identity or intent."
                    ),
                )
            )
        return findings
