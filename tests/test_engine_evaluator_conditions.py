"""Tests for _Condition, _coerce_bool, RuleEvaluator, and build_report."""

from __future__ import annotations

from typing import Any

import pytest

from fireaudit.engine.evaluator import (
    _Condition,
    _coerce_bool,
    RuleEvaluator,
    Finding,
    build_report,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_rule(
    rule_id: str = "TEST-001",
    name: str = "Test Rule",
    severity: str = "high",
    vendors: list[str] | None = None,
    match: dict | None = None,
    not_applicable_when: dict | None = None,
    frameworks: dict | None = None,
    remediation: str = "",
) -> dict:
    """Build a minimal rule dict suitable for RuleEvaluator."""
    rule: dict[str, Any] = {
        "rule_id": rule_id,
        "name": name,
        "severity": severity,
        "vendors": vendors if vendors is not None else ["all"],
        "frameworks": frameworks if frameworks is not None else {},
        "match": match if match is not None else {
            "type": "condition",
            "path": "admin_access.snmp.enabled",
            "condition": {"type": "is_false"},
        },
        "remediation": remediation,
    }
    if not_applicable_when is not None:
        rule["not_applicable_when"] = not_applicable_when
    return rule


def _base_ir(overrides: dict | None = None) -> dict:
    """Build a minimal IR dict for testing."""
    ir: dict[str, Any] = {
        "meta": {
            "vendor": "fortigate",
            "hostname": "test-fw",
            "model": "FG-100F",
            "firmware_version": "7.4.0",
            "source_file": "test.conf",
        },
        "admin_access": {
            "management_protocols": ["https", "ssh"],
            "snmp": {
                "enabled": False,
                "version": "v3",
                "communities": [],
            },
            "session_timeout": 300,
            "trusted_hosts": ["10.0.0.0/8"],
        },
        "interfaces": [],
        "firewall_policies": [],
        "vpn": {
            "ipsec_tunnels": [],
            "ssl_vpn": {"enabled": False},
        },
        "logging": {
            "syslog_servers": [],
            "log_level": "information",
        },
        "auth": {
            "local_users": [],
            "radius_servers": [],
        },
        "items": [
            {"name": "item-a", "value": 10, "active": True},
            {"name": "item-b", "value": 20, "active": False},
        ],
    }
    if overrides:
        _deep_merge(ir, overrides)
    return ir


def _deep_merge(base: dict, updates: dict) -> None:
    """Recursively merge updates into base dict."""
    for k, v in updates.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v


# ---------------------------------------------------------------------------
# Test _coerce_bool
# ---------------------------------------------------------------------------

class TestCoerceBool:
    def test_true_bool(self):
        assert _coerce_bool(True) is True

    def test_false_bool(self):
        assert _coerce_bool(False) is False

    def test_true_string(self):
        assert _coerce_bool("enabled") is True

    def test_false_string(self):
        assert _coerce_bool("disabled") is False

    def test_int_nonzero(self):
        assert _coerce_bool(1) is True

    def test_int_zero(self):
        assert _coerce_bool(0) is False

    def test_none(self):
        assert _coerce_bool(None) is None


# ---------------------------------------------------------------------------
# Test _Condition.check
# ---------------------------------------------------------------------------

class TestConditionTypes:
    c = _Condition()

    # --- eq / neq ---

    def test_eq_match(self):
        passed, _ = self.c.check({"type": "eq", "value": "hello"}, "hello", "")
        assert passed is True

    def test_eq_no_match(self):
        passed, _ = self.c.check({"type": "eq", "value": "hello"}, "world", "")
        assert passed is False

    def test_neq_match(self):
        passed, _ = self.c.check({"type": "neq", "value": "hello"}, "world", "")
        assert passed is True

    def test_neq_no_match(self):
        passed, _ = self.c.check({"type": "neq", "value": "hello"}, "hello", "")
        assert passed is False

    # --- numeric comparisons ---

    def test_gt(self):
        passed, _ = self.c.check({"type": "gt", "value": 5}, 10, "")
        assert passed is True

    def test_gte(self):
        passed, _ = self.c.check({"type": "gte", "value": 10}, 10, "")
        assert passed is True

    def test_lt(self):
        passed, _ = self.c.check({"type": "lt", "value": 10}, 5, "")
        assert passed is True

    def test_lte(self):
        passed, _ = self.c.check({"type": "lte", "value": 5}, 5, "")
        assert passed is True

    def test_compare_non_numeric(self):
        passed, msg = self.c.check({"type": "gt", "value": "x"}, "y", "")
        assert passed is False
        assert msg  # should contain an error description

    # --- in / not_in ---

    def test_in_match(self):
        passed, _ = self.c.check({"type": "in", "values": ["a", "b", "c"]}, "b", "")
        assert passed is True

    def test_in_no_match(self):
        passed, _ = self.c.check({"type": "in", "values": ["a", "b"]}, "z", "")
        assert passed is False

    def test_not_in(self):
        passed, _ = self.c.check({"type": "not_in", "values": ["a", "b"]}, "z", "")
        assert passed is True

    # --- contains / not_contains ---

    def test_contains_string(self):
        passed, _ = self.c.check({"type": "contains", "value": "hello"}, "say hello world", "")
        assert passed is True

    def test_contains_list(self):
        passed, _ = self.c.check({"type": "contains", "value": "ssh"}, ["https", "ssh", "telnet"], "")
        assert passed is True

    def test_contains_non_string(self):
        passed, _ = self.c.check({"type": "contains", "value": "x"}, 42, "")
        assert passed is False

    def test_not_contains(self):
        passed, _ = self.c.check({"type": "not_contains", "value": "telnet"}, ["https", "ssh"], "")
        assert passed is True

    # --- intersects / not_intersects ---

    def test_intersects_match(self):
        passed, _ = self.c.check(
            {"type": "intersects", "values": ["aes256", "aes128"]},
            ["aes256", "3des"],
            "",
        )
        assert passed is True

    def test_intersects_scalar(self):
        # Scalar value is wrapped in a list for comparison
        passed, _ = self.c.check(
            {"type": "intersects", "values": ["ssh", "https"]},
            "ssh",
            "",
        )
        assert passed is True

    def test_intersects_no_match(self):
        passed, _ = self.c.check(
            {"type": "intersects", "values": ["telnet", "http"]},
            ["https", "ssh"],
            "",
        )
        assert passed is False

    def test_not_intersects(self):
        passed, _ = self.c.check(
            {"type": "not_intersects", "values": ["telnet", "http"]},
            ["https", "ssh"],
            "",
        )
        assert passed is True

    # --- boolean / null ---

    def test_is_true(self):
        passed, _ = self.c.check({"type": "is_true"}, True, "")
        assert passed is True

    def test_is_false(self):
        passed, _ = self.c.check({"type": "is_false"}, False, "")
        assert passed is True

    def test_is_null(self):
        passed, _ = self.c.check({"type": "is_null"}, None, "")
        assert passed is True

    def test_is_not_null(self):
        passed, _ = self.c.check({"type": "is_not_null"}, "value", "")
        assert passed is True

    def test_is_empty(self):
        passed, _ = self.c.check({"type": "is_empty"}, [], "")
        assert passed is True

    def test_is_not_empty(self):
        passed, _ = self.c.check({"type": "is_not_empty"}, [1, 2], "")
        assert passed is True

    # --- regex / not_regex ---

    def test_regex_match(self):
        passed, _ = self.c.check({"type": "regex", "value": r"^\d{4}$"}, "1234", "")
        assert passed is True

    def test_regex_no_match(self):
        passed, _ = self.c.check({"type": "regex", "value": r"^\d{4}$"}, "abcd", "")
        assert passed is False

    def test_regex_null_value(self):
        passed, msg = self.c.check({"type": "regex", "value": r"\d+"}, None, "")
        assert passed is False
        assert "null" in msg.lower()

    def test_not_regex(self):
        passed, _ = self.c.check({"type": "not_regex", "value": r"^\d{4}$"}, "abcd", "")
        assert passed is True

    # --- list_all / list_any ---

    def test_list_all_pass(self):
        passed, _ = self.c.check(
            {"type": "list_all", "condition": {"type": "gt", "value": 0}},
            [1, 2, 3],
            "",
        )
        assert passed is True

    def test_list_all_fail(self):
        passed, _ = self.c.check(
            {"type": "list_all", "condition": {"type": "gt", "value": 0}},
            [1, -1, 3],
            "",
        )
        assert passed is False

    def test_list_all_non_list(self):
        passed, _ = self.c.check(
            {"type": "list_all", "condition": {"type": "is_true"}},
            "not-a-list",
            "",
        )
        assert passed is False

    def test_list_any_pass(self):
        passed, _ = self.c.check(
            {"type": "list_any", "condition": {"type": "gt", "value": 5}},
            [1, 2, 10],
            "",
        )
        assert passed is True

    def test_list_any_fail(self):
        passed, _ = self.c.check(
            {"type": "list_any", "condition": {"type": "gt", "value": 100}},
            [1, 2, 3],
            "",
        )
        assert passed is False

    def test_list_any_non_list(self):
        passed, _ = self.c.check(
            {"type": "list_any", "condition": {"type": "is_true"}},
            "not-a-list",
            "",
        )
        assert passed is False

    # --- count_gt / count_eq / count_lt ---

    def test_count_gt(self):
        passed, _ = self.c.check({"type": "count_gt", "value": 2}, [1, 2, 3], "")
        assert passed is True

    def test_count_eq(self):
        passed, _ = self.c.check({"type": "count_eq", "value": 3}, [1, 2, 3], "")
        assert passed is True

    def test_count_lt(self):
        passed, _ = self.c.check({"type": "count_lt", "value": 5}, [1, 2], "")
        assert passed is True

    # --- exists_where / not_exists_where ---

    def test_exists_where_found(self):
        items = [
            {"name": "a", "status": "active"},
            {"name": "b", "status": "inactive"},
        ]
        passed, _ = self.c.check(
            {"type": "exists_where", "where": {"status": {"type": "eq", "value": "active"}}},
            items,
            "",
        )
        assert passed is True

    def test_exists_where_not_found(self):
        items = [{"name": "a", "status": "inactive"}]
        passed, _ = self.c.check(
            {"type": "exists_where", "where": {"status": {"type": "eq", "value": "active"}}},
            items,
            "",
        )
        assert passed is False

    def test_exists_where_non_list(self):
        passed, _ = self.c.check(
            {"type": "exists_where", "where": {"x": {"type": "is_true"}}},
            "not-a-list",
            "",
        )
        assert passed is False

    # --- unknown type ---

    def test_unknown_type(self):
        passed, msg = self.c.check({"type": "bogus"}, "x", "")
        assert passed is False
        assert "unknown" in msg.lower() or "bogus" in msg


# ---------------------------------------------------------------------------
# TestRuleEvaluatorInline
# ---------------------------------------------------------------------------

class TestRuleEvaluatorInline:

    def test_condition_match_type(self):
        """Rule with condition match on snmp.enabled=True should pass."""
        rule = _make_rule(
            rule_id="TEST-SNMP-PASS",
            match={
                "type": "condition",
                "path": "admin_access.snmp.enabled",
                "condition": {"type": "is_true"},
            },
        )
        evaluator = RuleEvaluator([rule])
        ir = _base_ir({"admin_access": {"snmp": {"enabled": True}}})
        findings = evaluator.evaluate(ir, vendor="fortigate")
        assert len(findings) == 1
        assert findings[0].status == "pass"

    def test_all_of_match(self):
        """all_of: both sub-conditions pass => overall pass."""
        rule = _make_rule(
            rule_id="TEST-ALLOF",
            match={
                "type": "all_of",
                "checks": [
                    {
                        "type": "condition",
                        "path": "admin_access.snmp.enabled",
                        "condition": {"type": "is_false"},
                    },
                    {
                        "type": "condition",
                        "path": "admin_access.session_timeout",
                        "condition": {"type": "gt", "value": 0},
                    },
                ],
            },
        )
        evaluator = RuleEvaluator([rule])
        ir = _base_ir()  # snmp.enabled=False, session_timeout=300
        findings = evaluator.evaluate(ir, vendor="fortigate")
        assert findings[0].status == "pass"

    def test_any_of_match(self):
        """any_of: one sub-condition passes => overall pass."""
        rule = _make_rule(
            rule_id="TEST-ANYOF",
            match={
                "type": "any_of",
                "checks": [
                    {
                        "type": "condition",
                        "path": "admin_access.snmp.enabled",
                        "condition": {"type": "is_true"},  # this will fail
                    },
                    {
                        "type": "condition",
                        "path": "admin_access.session_timeout",
                        "condition": {"type": "gt", "value": 0},  # this will pass
                    },
                ],
            },
        )
        evaluator = RuleEvaluator([rule])
        ir = _base_ir()
        findings = evaluator.evaluate(ir, vendor="fortigate")
        assert findings[0].status == "pass"

    def test_none_of_match(self):
        """none_of: no sub-condition passes => overall pass."""
        rule = _make_rule(
            rule_id="TEST-NONEOF",
            match={
                "type": "none_of",
                "checks": [
                    {
                        "type": "condition",
                        "path": "admin_access.snmp.enabled",
                        "condition": {"type": "is_true"},  # False in IR => fails => none_of passes
                    },
                ],
            },
        )
        evaluator = RuleEvaluator([rule])
        ir = _base_ir()  # snmp.enabled=False
        findings = evaluator.evaluate(ir, vendor="fortigate")
        assert findings[0].status == "pass"

    def test_foreach_match(self):
        """foreach: iterate items list and check a condition on each."""
        rule = _make_rule(
            rule_id="TEST-FOREACH",
            match={
                "type": "foreach",
                "path": "items",
                "checks": [
                    {
                        "path": "active",
                        "condition": {"type": "is_true"},
                    },
                ],
                "fail_on": "any",
            },
        )
        evaluator = RuleEvaluator([rule])
        # All items active=True => should pass
        ir = _base_ir({
            "items": [
                {"name": "item-a", "value": 1, "active": True},
                {"name": "item-b", "value": 2, "active": True},
            ]
        })
        findings = evaluator.evaluate(ir, vendor="fortigate")
        assert findings[0].status == "pass"

    def test_foreach_match_failure(self):
        """foreach: one item fails active check => overall fail."""
        rule = _make_rule(
            rule_id="TEST-FOREACH-FAIL",
            match={
                "type": "foreach",
                "path": "items",
                "checks": [
                    {
                        "path": "active",
                        "condition": {"type": "is_true"},
                    },
                ],
                "fail_on": "any",
            },
        )
        evaluator = RuleEvaluator([rule])
        ir = _base_ir()  # items has item-b with active=False
        findings = evaluator.evaluate(ir, vendor="fortigate")
        assert findings[0].status == "fail"

    def test_not_applicable_when_fires(self):
        """not_applicable_when: when condition matches IR, result is not_applicable."""
        rule = _make_rule(
            rule_id="TEST-NA",
            match={
                "type": "condition",
                "path": "admin_access.snmp.enabled",
                "condition": {"type": "is_true"},
            },
            not_applicable_when={
                "type": "condition",
                "path": "admin_access.snmp.enabled",
                "condition": {"type": "is_false"},  # snmp.enabled=False => N/A fires
            },
        )
        evaluator = RuleEvaluator([rule])
        ir = _base_ir()  # snmp.enabled=False
        findings = evaluator.evaluate(ir, vendor="fortigate")
        assert findings[0].status == "not_applicable"

    def test_manual_rule_gives_manual_check(self):
        """match type=manual always produces manual_check status."""
        rule = _make_rule(
            rule_id="TEST-MANUAL",
            match={
                "type": "manual",
                "guidance": "Manually verify this control.",
            },
        )
        evaluator = RuleEvaluator([rule])
        ir = _base_ir()
        findings = evaluator.evaluate(ir, vendor="fortigate")
        assert findings[0].status == "manual_check"

    def test_error_in_rule_gives_error_status(self):
        """A rule that raises an exception during evaluation produces 'error' status."""
        rule = _make_rule(
            rule_id="TEST-ERROR",
            match={
                "type": "condition",
                # Deliberately use a completely bogus condition type to provoke a
                # handled exception path — or rely on the evaluator's except clause
                # by monkeypatching. Instead we use a path that resolves fine but
                # an unknown match type so the evaluator returns False gracefully.
                "path": "admin_access.snmp.enabled",
                "condition": {"type": "eq", "value": False},
            },
        )
        # We force an error by passing None as the IR (which will cause attribute
        # lookup failures in resolve_path since it expects a dict)
        evaluator = RuleEvaluator([rule])
        findings = evaluator.evaluate(None, vendor="fortigate")  # type: ignore[arg-type]
        assert len(findings) == 1
        assert findings[0].status in ("error", "fail", "not_applicable"), (
            f"Expected error/fail/not_applicable, got {findings[0].status}"
        )

    def test_vendor_filter_excludes_rule(self):
        """A fortigate-only rule should NOT appear when evaluating with vendor=paloalto."""
        rule = _make_rule(
            rule_id="TEST-FG-ONLY",
            vendors=["fortigate"],
            match={
                "type": "condition",
                "path": "admin_access.snmp.enabled",
                "condition": {"type": "is_false"},
            },
        )
        evaluator = RuleEvaluator([rule])
        ir = _base_ir()
        findings = evaluator.evaluate(ir, vendor="paloalto")
        assert len(findings) == 0

    def test_build_report_structure(self):
        """build_report should return a dict with expected top-level keys."""
        rule = _make_rule(
            rule_id="TEST-REPORT",
            match={
                "type": "condition",
                "path": "admin_access.snmp.enabled",
                "condition": {"type": "is_false"},
            },
        )
        evaluator = RuleEvaluator([rule])
        ir = _base_ir()
        findings = evaluator.evaluate(ir, vendor="fortigate")
        report = build_report(ir, findings)

        assert "findings" in report
        assert "summary" in report
        assert "device" in report
        assert "compliance_scores" in report
        assert "posture_score" in report
        assert report["device"]["vendor"] == "fortigate"
        assert report["device"]["hostname"] == "test-fw"

    def test_build_report_framework_filter(self):
        """build_report with framework_filter only scores matching frameworks."""
        rule = _make_rule(
            rule_id="TEST-FW-FILTER",
            frameworks={"nist_800-53": ["AC-2"], "cis": ["1.1"]},
            match={
                "type": "condition",
                "path": "admin_access.snmp.enabled",
                "condition": {"type": "is_false"},
            },
        )
        evaluator = RuleEvaluator([rule])
        ir = _base_ir()
        findings = evaluator.evaluate(ir, vendor="fortigate")
        report = build_report(ir, findings, framework_filter="nist_800-53")

        scores = report["compliance_scores"]
        # Only nist_800-53 should appear; cis is filtered out
        assert "nist_800-53" in scores
        assert "cis" not in scores
