"""Claude API semantic analysis for ambiguous findings (Layer 4).

Only called when --semantic flag is provided and findings are ambiguous
(verdict REVIEW or SUSPICIOUS with moderate security_tool_score).
"""

from __future__ import annotations

import json
import logging
import os

from waingro.models import Finding, ParsedSkill

logger = logging.getLogger(__name__)

SEMANTIC_PROMPT = """Analyze this OpenClaw agent skill file for security.

The following detection rules fired:

{findings_summary}

Determine whether each pattern is in an EXECUTION context (the skill instructs
the agent to perform this action) or a DETECTION context (the skill instructs
the agent to identify/block this pattern in other content).

Use the submit_verdict tool to report your analysis.

SKILL.md content:
```
{skill_content}
```"""

VERDICT_TOOL = {
    "name": "submit_verdict",
    "description": "Submit the security analysis verdict for this skill",
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["MALICIOUS", "SUSPICIOUS", "REVIEW", "CLEAN"],
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
            },
            "is_security_tool": {
                "type": "boolean",
            },
            "reasoning": {
                "type": "string",
            },
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string"},
                        "intent": {
                            "type": "string",
                            "enum": ["offensive", "defensive", "ambiguous"],
                        },
                    },
                },
            },
        },
        "required": ["verdict", "confidence", "is_security_tool", "reasoning"],
    },
}

DEFAULT_MODEL = "claude-sonnet-4-20250514"
DEFAULT_BUDGET = 5.00
MAX_SKILL_TOKENS = 8000


class SemanticAnalyzer:
    """Claude API-based semantic analysis for ambiguous skills."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        budget: float = DEFAULT_BUDGET,
    ):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model
        self.budget = budget
        self._spent = 0.0
        self._client = None

    @property
    def client(self):
        if self._client is None:
            if not self.api_key:
                msg = (
                    "ANTHROPIC_API_KEY not set. Set the environment variable or "
                    "pass api_key to SemanticAnalyzer."
                )
                raise RuntimeError(msg)
            try:
                import anthropic
            except ImportError as e:
                msg = "anthropic package required for --semantic. Install: pip install anthropic"
                raise RuntimeError(msg) from e
            self._client = anthropic.Anthropic(api_key=self.api_key)
        return self._client

    @property
    def budget_remaining(self) -> float:
        return self.budget - self._spent

    def should_analyze(
        self, verdict: str, security_tool_score: float,
    ) -> bool:
        """Determine if a skill needs semantic analysis."""
        if self._spent >= self.budget:
            return False
        if verdict not in ("REVIEW", "SUSPICIOUS"):
            return False
        return 0.3 <= security_tool_score <= 0.7

    def analyze(
        self, skill: ParsedSkill, findings: list[Finding],
    ) -> dict:
        """Run semantic analysis on a skill via tool_use."""
        findings_summary = "\n".join(
            f"- {f.rule_id} ({f.severity.value}): {f.title} — "
            f"matched: {f.matched_content[:100]}"
            for f in findings[:15]
        )

        content = skill.body[:MAX_SKILL_TOKENS * 4]
        for bf in skill.bundled_content:
            remaining = MAX_SKILL_TOKENS * 4 - len(content)
            if remaining > 200:
                content += f"\n\n--- Bundled: {bf.path.name} ---\n"
                content += bf.content[:remaining]

        prompt = SEMANTIC_PROMPT.format(
            findings_summary=findings_summary,
            skill_content=content,
        )

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=512,
                tools=[VERDICT_TOOL],
                tool_choice={"type": "tool", "name": "submit_verdict"},
                messages=[{"role": "user", "content": prompt}],
            )

            # Track cost
            input_tokens = response.usage.input_tokens
            output_tokens = response.usage.output_tokens
            cost = (input_tokens * 3 + output_tokens * 15) / 1_000_000
            self._spent += cost

            # Extract tool_use result — already parsed JSON
            for block in response.content:
                if block.type == "tool_use" and block.name == "submit_verdict":
                    return self._normalize_result(block.input)

            # Fallback: try text content with JSON parsing
            for block in response.content:
                if block.type == "text":
                    return self._parse_text_response(block.text, skill.metadata.name)

            logger.warning("No tool_use block in response for %s", skill.metadata.name)
            return self._default_result()

        except Exception:
            logger.exception("Semantic analysis failed for %s", skill.metadata.name)
            return self._default_result()

    def _normalize_result(self, tool_input: dict) -> dict:
        """Convert tool_use input to the internal result format."""
        is_security = tool_input.get("is_security_tool", False)
        verdict = tool_input.get("verdict", "SUSPICIOUS")

        if is_security:
            classification = "security_tool"
        elif verdict == "MALICIOUS":
            classification = "malicious"
        else:
            classification = "ambiguous"

        finding_contexts = []
        for f in tool_input.get("findings", []):
            intent = f.get("intent", "ambiguous")
            context = {
                "offensive": "execution",
                "defensive": "detection",
                "ambiguous": "ambiguous",
            }.get(intent, "ambiguous")
            finding_contexts.append({
                "rule_id": f.get("pattern", ""),
                "context": context,
                "reasoning": tool_input.get("reasoning", ""),
            })

        return {
            "skill_classification": classification,
            "verdict": verdict,
            "confidence": tool_input.get("confidence", 0.5),
            "is_security_tool": is_security,
            "reasoning": tool_input.get("reasoning", ""),
            "findings": finding_contexts,
        }

    def _parse_text_response(self, text: str, skill_name: str) -> dict:
        """Fallback: parse raw text as JSON."""
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[: text.rfind("```")]
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            logger.warning("Semantic text response not JSON for %s", skill_name)
            return self._default_result()

    @staticmethod
    def _default_result() -> dict:
        return {"skill_classification": "ambiguous", "findings": []}

    def apply_results(
        self, findings: list[Finding], result: dict,
    ) -> list[Finding]:
        """Apply semantic analysis results to findings."""
        classification = result.get("skill_classification", "ambiguous")
        finding_contexts = {
            f.get("rule_id", ""): f.get("context", "ambiguous")
            for f in result.get("findings", [])
        }

        for finding in findings:
            if finding.rule_id == "NET-002":
                continue

            ctx = finding_contexts.get(finding.rule_id, "ambiguous")
            if classification == "security_tool" or ctx == "detection":
                finding.confidence = 0.1
                finding.context_note = (
                    f"Semantic analysis: {classification} "
                    f"(context={ctx}). {finding.context_note or ''}"
                )
            elif classification == "malicious" or ctx == "execution":
                finding.confidence = 1.0
                finding.context_note = (
                    f"Semantic analysis confirmed: {classification} "
                    f"(context={ctx}). {finding.context_note or ''}"
                )

        return findings
