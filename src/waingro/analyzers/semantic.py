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

SEMANTIC_PROMPT = """You are analyzing an OpenClaw agent skill file (SKILL.md) for security.

The following detection rules fired on this skill:

{findings_summary}

For each finding, determine:
1. Is the pattern in an EXECUTION context (skill instructs the agent to do this)?
2. Or in a DETECTION context (skill instructs the agent to identify/block this)?

Return JSON only, no other text:
{{
  "skill_classification": "malicious" | "security_tool" | "ambiguous",
  "findings": [
    {{
      "rule_id": "...",
      "context": "execution" | "detection" | "ambiguous",
      "reasoning": "brief explanation"
    }}
  ]
}}

SKILL.md content:
```
{skill_content}
```"""

DEFAULT_MODEL = "claude-sonnet-4-20250514"
DEFAULT_BUDGET = 5.00
MAX_SKILL_TOKENS = 8000  # ~8K tokens, most skills are under 4K


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
        # Ambiguous zone: security_tool_score between 0.3 and 0.7
        return 0.3 <= security_tool_score <= 0.7

    def analyze(
        self, skill: ParsedSkill, findings: list[Finding],
    ) -> dict:
        """Run semantic analysis on a skill. Returns API classification."""
        findings_summary = "\n".join(
            f"- {f.rule_id} ({f.severity.value}): {f.title} — "
            f"matched: {f.matched_content[:100]}"
            for f in findings[:15]  # cap to control token usage
        )

        # Truncate skill content
        content = skill.body[:MAX_SKILL_TOKENS * 4]  # rough char-to-token ratio
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
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )

            # Track cost (approximate: $3/M input, $15/M output for Sonnet)
            input_tokens = response.usage.input_tokens
            output_tokens = response.usage.output_tokens
            cost = (input_tokens * 3 + output_tokens * 15) / 1_000_000
            self._spent += cost

            text = response.content[0].text
            return json.loads(text)

        except json.JSONDecodeError:
            logger.warning("Semantic analysis returned non-JSON for %s", skill.metadata.name)
            return {"skill_classification": "ambiguous", "findings": []}
        except Exception:
            logger.exception("Semantic analysis failed for %s", skill.metadata.name)
            return {"skill_classification": "ambiguous", "findings": []}

    def apply_results(
        self, findings: list[Finding], result: dict,
    ) -> list[Finding]:
        """Apply semantic analysis results to findings."""
        classification = result.get("skill_classification", "ambiguous")
        finding_contexts = {
            f["rule_id"]: f["context"]
            for f in result.get("findings", [])
        }

        for finding in findings:
            if finding.rule_id == "NET-002":
                continue  # Never adjust C2 IP findings

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
