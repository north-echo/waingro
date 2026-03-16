"""Rule base class and registry."""

from abc import ABC, abstractmethod

from waingro.models import Finding, ParsedSkill

_RULES: list[type["Rule"]] = []


class Rule(ABC):
    """Base class for all detection rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique rule identifier, e.g. EXEC-001"""

    @property
    @abstractmethod
    def title(self) -> str:
        """Human-readable rule name"""

    @property
    @abstractmethod
    def description(self) -> str:
        """What this rule detects"""

    @abstractmethod
    def evaluate(self, skill: ParsedSkill) -> list[Finding]:
        """Run the rule against a parsed skill. Return findings."""


def register_rule(cls: type[Rule]) -> type[Rule]:
    """Decorator to register a rule class."""
    _RULES.append(cls)
    return cls


def get_all_rules() -> list[Rule]:
    """Instantiate and return all registered rules."""
    return [cls() for cls in _RULES]
