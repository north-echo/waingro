"""Static analyzer: runs all registered rules against a parsed skill."""

# Import all rule modules to trigger registration
import waingro.rules.execution  # noqa: F401
import waingro.rules.exfiltration  # noqa: F401
import waingro.rules.injection  # noqa: F401
import waingro.rules.network  # noqa: F401
import waingro.rules.obfuscation  # noqa: F401
import waingro.rules.persistence  # noqa: F401
import waingro.rules.social  # noqa: F401
from waingro.models import Finding, ParsedSkill
from waingro.rules import get_all_rules


def run_static_analysis(skill: ParsedSkill) -> tuple[list[Finding], int]:
    """Run all rules against a parsed skill. Returns (findings, rules_evaluated)."""
    rules = get_all_rules()
    findings: list[Finding] = []
    for rule in rules:
        findings.extend(rule.evaluate(skill))
    return findings, len(rules)
