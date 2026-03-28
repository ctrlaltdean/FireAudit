"""Tests for fireaudit/engine/loader.py — RuleLoader validation and loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from fireaudit.engine.loader import RuleLoader, RuleLoadError

# Path to the real bundled rules directory
REAL_RULES_DIR = Path(__file__).parent.parent / "rules"


# ---------------------------------------------------------------------------
# Minimal valid rule dict helpers
# ---------------------------------------------------------------------------

def _write_rule(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


MINIMAL_RULE = """\
rule_id: TEST-001
name: Test Rule
severity: info
match:
  type: condition
  path: admin_access.snmp.enabled
  condition:
    type: is_false
vendors:
  - all
"""


# ---------------------------------------------------------------------------
# TestRuleLoaderErrors
# ---------------------------------------------------------------------------

class TestRuleLoaderErrors:
    def test_missing_directory(self):
        loader = RuleLoader("/nonexistent/path/to/rules")
        with pytest.raises(RuleLoadError, match="not found"):
            loader.load_all()

    def test_yaml_parse_error(self, tmp_path):
        bad_file = tmp_path / "bad.yaml"
        _write_rule(bad_file, "key: :\n bad indentation [[[")
        loader = RuleLoader(tmp_path)
        # Should not raise — malformed file is skipped with a warning
        rules = loader.load_all()
        assert isinstance(rules, list)

    def test_empty_yaml_file(self, tmp_path):
        empty_file = tmp_path / "empty.yaml"
        empty_file.write_text("", encoding="utf-8")
        loader = RuleLoader(tmp_path)
        rules = loader.load_all()
        assert rules == []

    def test_list_of_rules(self, tmp_path):
        rules_file = tmp_path / "two_rules.yaml"
        content = """\
- rule_id: LIST-001
  name: First Rule
  severity: info
  match:
    type: condition
    path: foo
    condition:
      type: is_true
  vendors:
    - all

- rule_id: LIST-002
  name: Second Rule
  severity: high
  match:
    type: condition
    path: bar
    condition:
      type: is_false
  vendors:
    - all
"""
        _write_rule(rules_file, content)
        loader = RuleLoader(tmp_path)
        rules = loader.load_all()
        assert len(rules) == 2
        rule_ids = {r["rule_id"] for r in rules}
        assert "LIST-001" in rule_ids
        assert "LIST-002" in rule_ids

    def test_missing_required_field(self, tmp_path):
        # Rule missing the required "match" field
        bad_rule = tmp_path / "missing_match.yaml"
        content = """\
rule_id: BAD-001
name: Missing Match Field
severity: info
vendors:
  - all
"""
        _write_rule(bad_rule, content)
        loader = RuleLoader(tmp_path)
        # Should not crash; invalid rule is skipped
        rules = loader.load_all()
        rule_ids = [r["rule_id"] for r in rules]
        assert "BAD-001" not in rule_ids

    def test_invalid_severity(self, tmp_path):
        bad_rule = tmp_path / "bad_severity.yaml"
        content = """\
rule_id: BAD-002
name: Invalid Severity
severity: extreme
match:
  type: condition
  path: foo
  condition:
    type: is_true
vendors:
  - all
"""
        _write_rule(bad_rule, content)
        loader = RuleLoader(tmp_path)
        rules = loader.load_all()
        rule_ids = [r["rule_id"] for r in rules]
        assert "BAD-002" not in rule_ids

    def test_vendor_filter_all(self, tmp_path):
        rule_file = tmp_path / "all_vendors.yaml"
        content = """\
rule_id: VENDOR-ALL-001
name: Applies To All
severity: info
match:
  type: condition
  path: foo
  condition:
    type: is_true
vendors:
  - all
"""
        _write_rule(rule_file, content)
        loader = RuleLoader(tmp_path)
        rules = loader.load_for_vendor("paloalto")
        assert any(r["rule_id"] == "VENDOR-ALL-001" for r in rules)

    def test_vendor_filter_specific(self, tmp_path):
        rule_file = tmp_path / "fortigate_only.yaml"
        content = """\
rule_id: VENDOR-FG-001
name: FortiGate Only
severity: info
match:
  type: condition
  path: foo
  condition:
    type: is_true
vendors:
  - fortigate
"""
        _write_rule(rule_file, content)
        loader = RuleLoader(tmp_path)
        rules = loader.load_for_vendor("paloalto")
        rule_ids = [r["rule_id"] for r in rules]
        assert "VENDOR-FG-001" not in rule_ids

    def test_vendor_filter_empty_list(self, tmp_path):
        rule_file = tmp_path / "empty_vendors.yaml"
        content = """\
rule_id: VENDOR-EMPTY-001
name: Empty Vendors List
severity: info
match:
  type: condition
  path: foo
  condition:
    type: is_true
vendors: []
"""
        _write_rule(rule_file, content)
        loader = RuleLoader(tmp_path)
        # Empty vendors list should apply to any vendor
        rules = loader.load_for_vendor("sonicwall")
        assert any(r["rule_id"] == "VENDOR-EMPTY-001" for r in rules)

    def test_load_for_vendor(self):
        if not REAL_RULES_DIR.exists():
            pytest.skip("Bundled rules directory not found")
        loader = RuleLoader(REAL_RULES_DIR)
        rules = loader.load_for_vendor("fortigate")
        assert len(rules) > 0, "Expected at least one rule for fortigate"
        for rule in rules:
            vendors = [v.lower() for v in rule.get("vendors", ["all"])]
            assert "all" in vendors or "fortigate" in vendors, (
                f"Rule {rule['rule_id']} has vendors {vendors!r} — should match fortigate"
            )
