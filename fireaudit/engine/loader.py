"""Rule loader — reads YAML rule files from the rules/ directory."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

log = logging.getLogger(__name__)

REQUIRED_FIELDS = {"rule_id", "name", "severity", "match"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class RuleLoadError(Exception):
    pass


class RuleLoader:
    """Loads and validates YAML rule files from a directory."""

    def __init__(self, rules_dir: str | Path) -> None:
        self.rules_dir = Path(rules_dir)

    def load_all(self) -> list[dict]:
        """Load all .yaml/.yml rule files from the rules directory (recursive)."""
        if not self.rules_dir.exists():
            raise RuleLoadError(f"Rules directory not found: {self.rules_dir}")

        rules: list[dict] = []
        for path in sorted(self.rules_dir.rglob("*.yaml")) + sorted(self.rules_dir.rglob("*.yml")):
            try:
                loaded = self._load_file(path)
                rules.extend(loaded)
            except RuleLoadError as e:
                log.warning("Skipping %s: %s", path, e)

        log.info("Loaded %d rules from %s", len(rules), self.rules_dir)
        return rules

    def load_for_vendor(self, vendor: str) -> list[dict]:
        """Load only rules applicable to the given vendor."""
        all_rules = self.load_all()
        return [r for r in all_rules if self._applies_to_vendor(r, vendor)]

    def _load_file(self, path: Path) -> list[dict]:
        try:
            with path.open(encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise RuleLoadError(f"YAML parse error: {e}") from e

        if data is None:
            return []

        # A file may contain a single rule dict or a list of rules
        if isinstance(data, dict):
            rules = [data]
        elif isinstance(data, list):
            rules = data
        else:
            raise RuleLoadError(f"Expected dict or list, got {type(data)}")

        validated: list[dict] = []
        for rule in rules:
            try:
                validated.append(self._validate(rule, path))
            except RuleLoadError as e:
                log.warning("Invalid rule in %s: %s", path, e)

        return validated

    def _validate(self, rule: dict, path: Path) -> dict:
        missing = REQUIRED_FIELDS - set(rule.keys())
        if missing:
            raise RuleLoadError(f"Missing required fields: {missing}")

        severity = rule.get("severity", "").lower()
        if severity not in VALID_SEVERITIES:
            raise RuleLoadError(f"Invalid severity '{severity}'. Must be one of {VALID_SEVERITIES}")

        rule["severity"] = severity
        rule.setdefault("description", "")
        rule.setdefault("remediation", "")
        rule.setdefault("frameworks", {})
        rule.setdefault("vendors", ["all"])
        rule.setdefault("_source_file", str(path))

        return rule

    @staticmethod
    def _applies_to_vendor(rule: dict, vendor: str) -> bool:
        vendors = rule.get("vendors", ["all"])
        if not vendors:
            return True
        vendors_lower = [v.lower() for v in vendors]
        return "all" in vendors_lower or vendor.lower() in vendors_lower
