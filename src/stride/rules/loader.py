"""Rule loader — reads STRIDE rules from YAML files."""

import logging
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


class Rule:
    """A single STRIDE rule definition."""

    def __init__(self, data: dict):
        self.id: str = data["id"]
        self.category: str = data["category"]
        self.title: str = data["title"]
        self.description: str = data.get("description", "")
        self.applies_to: list[str] = data.get("applies_to", [])
        self.condition: dict = data.get("condition", {})
        self.severity: str = data.get("severity", "Medium")
        self.confidence: float = data.get("confidence", 0.7)
        self.mitigations: list[str] = data.get("mitigations", [])
        self.cwe_ids: list[str] = data.get("cwe_ids", [])
        self.attack_vector: Optional[str] = data.get("attack_vector")

    def __repr__(self) -> str:
        return f"Rule({self.id}: {self.title})"


class RuleLoader:
    """Loads STRIDE rules from YAML files."""

    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = rules_dir or Path("rules")
        self._rules: list[Rule] = []

    def load(self) -> list[Rule]:
        """Load all rules from the rules directory."""
        self._rules = []

        if not self.rules_dir.exists():
            logger.warning(f"Rules directory not found: {self.rules_dir}")
            return self._rules

        for yaml_file in self.rules_dir.glob("*.yaml"):
            rules = self._load_file(yaml_file)
            self._rules.extend(rules)

        # Also check for .yml extension
        for yml_file in self.rules_dir.glob("*.yml"):
            rules = self._load_file(yml_file)
            self._rules.extend(rules)

        logger.info(f"Loaded {len(self._rules)} STRIDE rules from {self.rules_dir}")
        return self._rules

    def _load_file(self, path: Path) -> list[Rule]:
        """Load rules from a single YAML file."""
        try:
            content = path.read_text(encoding="utf-8")
            data = yaml.safe_load(content)

            if not data or "rules" not in data:
                return []

            rules = []
            for rule_data in data["rules"]:
                try:
                    rule = Rule(rule_data)
                    rules.append(rule)
                except KeyError as e:
                    logger.warning(f"Invalid rule in {path}: missing {e}")
                    continue

            return rules

        except Exception as e:
            logger.error(f"Failed to load rules from {path}: {e}")
            return []

    def get_rules_for_element_type(self, element_type: str) -> list[Rule]:
        """Get all rules applicable to a specific element type."""
        return [r for r in self._rules if element_type in r.applies_to]

    def get_rules_for_category(self, category: str) -> list[Rule]:
        """Get all rules for a specific STRIDE category."""
        return [r for r in self._rules if r.category == category]

    @property
    def rules(self) -> list[Rule]:
        """Get all loaded rules."""
        return self._rules
