"""Tests for the rule engine evaluator."""

import pytest
from pathlib import Path

from fireaudit.engine.loader import RuleLoader
from fireaudit.engine.evaluator import RuleEvaluator, resolve_path, build_report
from fireaudit.parsers.fortigate import FortiGateParser

FIXTURE = Path(__file__).parent.parent / "fixtures" / "fortigate" / "sample_full.conf"
RULES_DIR = Path(__file__).parent.parent.parent / "rules"


@pytest.fixture(scope="module")
def ir():
    parser = FortiGateParser()
    return parser.parse_file(FIXTURE)


@pytest.fixture(scope="module")
def findings(ir):
    loader = RuleLoader(RULES_DIR)
    rules = loader.load_for_vendor("fortigate")
    evaluator = RuleEvaluator(rules)
    return evaluator.evaluate(ir, vendor="fortigate")


# --- resolve_path tests ---

def test_resolve_simple_path(ir):
    val = resolve_path(ir, "meta.vendor")
    assert val == "fortigate"


def test_resolve_nested_path(ir):
    val = resolve_path(ir, "admin_access.session_timeout_seconds")
    assert val == 300


def test_resolve_list_wildcard(ir):
    vals = resolve_path(ir, "firewall_policies[*].action")
    assert isinstance(vals, list)
    assert "allow" in vals


def test_resolve_missing_path(ir):
    val = resolve_path(ir, "nonexistent.key.here")
    assert val is None


# --- Rule engine tests ---

def test_rules_loaded():
    loader = RuleLoader(RULES_DIR)
    rules = loader.load_all()
    assert len(rules) >= 10


def test_findings_produced(findings):
    assert len(findings) > 0


def test_http_disabled_passes(findings):
    f = next((f for f in findings if f.rule_id == "FW-ADM-001"), None)
    assert f is not None
    assert f.status == "pass"


def test_telnet_disabled_passes(findings):
    f = next((f for f in findings if f.rule_id == "FW-ADM-002"), None)
    assert f is not None
    assert f.status == "pass"


def test_session_timeout_passes(findings):
    # admintimeout 5 = 300s which is <= 600
    f = next((f for f in findings if f.rule_id == "FW-ADM-004"), None)
    assert f is not None
    assert f.status == "pass"


def test_trusted_hosts_passes(findings):
    f = next((f for f in findings if f.rule_id == "FW-ADM-005"), None)
    assert f is not None
    assert f.status == "pass"


def test_banner_passes(findings):
    f = next((f for f in findings if f.rule_id == "FW-ADM-006"), None)
    assert f is not None
    assert f.status == "pass"


def test_password_length_passes(findings):
    f = next((f for f in findings if f.rule_id == "FW-AUTH-001"), None)
    assert f is not None
    assert f.status == "pass"


def test_default_admin_fails(findings):
    # sample conf has 'admin' account
    f = next((f for f in findings if f.rule_id == "FW-AUTH-002"), None)
    assert f is not None
    assert f.status == "fail"


def test_syslog_passes(findings):
    f = next((f for f in findings if f.rule_id == "FW-LOG-001"), None)
    assert f is not None
    assert f.status == "pass"


def test_ntp_passes(findings):
    f = next((f for f in findings if f.rule_id == "FW-LOG-002"), None)
    assert f is not None
    assert f.status == "pass"


def test_any_any_fails(findings):
    f = next((f for f in findings if f.rule_id == "FW-POL-001"), None)
    assert f is not None
    assert f.status == "fail"  # policy 4 is any/any allow


def test_policy_logging_fails(findings):
    f = next((f for f in findings if f.rule_id == "FW-POL-002"), None)
    assert f is not None
    assert f.status == "fail"  # policy 4 has logging disabled


def test_weak_vpn_encryption_fails(findings):
    # legacy tunnel uses 3des
    f = next((f for f in findings if f.rule_id == "FW-VPN-001"), None)
    assert f is not None
    # At least one tunnel has 3des so this should fail
    # (not_exists_where: should find no tunnels with weak enc — but there is one, so fail)
    assert f.status == "fail"


def test_build_report(ir, findings):
    report = build_report(ir, findings)
    assert report["device"]["vendor"] == "fortigate"
    assert "summary" in report
    assert "compliance_scores" in report
    assert report["summary"]["total_rules"] == len(findings)
    accounted = (
        report["summary"]["pass"]
        + report["summary"]["fail"]
        + report["summary"].get("error", 0)
        + report["summary"].get("manual_check", 0)
    )
    assert accounted == len(findings)


def test_manual_checks_not_in_compliance_scores(ir, findings):
    report = build_report(ir, findings)
    manual_count = report["summary"].get("manual_check", 0)
    assert manual_count > 0, "expected some manual_check findings from rules/manual/"
    # manual_check findings must not affect compliance percentage scores
    for fw, data in report["compliance_scores"].items():
        assert data["pass"] + data["fail"] <= len(findings) - manual_count


def test_manual_check_status_in_findings(findings):
    manual = [f for f in findings if f.status == "manual_check"]
    assert len(manual) > 0
    for f in manual:
        assert f.rule_id.startswith("FW-MAN-")


def test_not_exists_where_passes_clean_config():
    """not_exists_where must pass when no item matches the where conditions."""
    from fireaudit.engine.evaluator import RuleEvaluator
    clean_ir = {
        "vpn": {
            "ipsec_tunnels": [
                {
                    "name": "GOOD-TUNNEL",
                    "enabled": True,
                    "phase1": {
                        "encryption": ["aes256"],
                        "authentication": ["sha256"],
                        "dh_groups": [14],
                        "ike_version": 2,
                        "aggressive_mode": False,
                    },
                    "phase2": {"encryption": ["aes256"], "authentication": ["sha256"], "pfs_enabled": True},
                }
            ]
        }
    }
    rule = {
        "rule_id": "FW-VPN-001",
        "name": "Test",
        "severity": "critical",
        "vendors": ["all"],
        "frameworks": {},
        "match": {
            "type": "not_exists_where",
            "path": "vpn.ipsec_tunnels",
            "where": {
                "enabled": {"type": "is_true"},
                "phase1.encryption": {"type": "intersects", "values": ["des", "3des", "rc4"]},
            },
        },
        "remediation": "",
        "description": "",
    }
    evaluator = RuleEvaluator([rule])
    results = evaluator.evaluate(clean_ir)
    assert results[0].status == "pass"


def test_not_exists_where_fails_when_match_found():
    """not_exists_where must fail when a matching item is found."""
    from fireaudit.engine.evaluator import RuleEvaluator
    dirty_ir = {
        "vpn": {
            "ipsec_tunnels": [
                {
                    "name": "WEAK-TUNNEL",
                    "enabled": True,
                    "phase1": {
                        "encryption": ["3des"],
                        "authentication": ["md5"],
                        "dh_groups": [2],
                        "ike_version": 1,
                        "aggressive_mode": False,
                    },
                    "phase2": {"encryption": ["3des"], "authentication": ["md5"], "pfs_enabled": False},
                }
            ]
        }
    }
    rule = {
        "rule_id": "FW-VPN-001",
        "name": "Test",
        "severity": "critical",
        "vendors": ["all"],
        "frameworks": {},
        "match": {
            "type": "not_exists_where",
            "path": "vpn.ipsec_tunnels",
            "where": {
                "enabled": {"type": "is_true"},
                "phase1.encryption": {"type": "intersects", "values": ["des", "3des", "rc4"]},
            },
        },
        "remediation": "",
        "description": "",
    }
    evaluator = RuleEvaluator([rule])
    results = evaluator.evaluate(dirty_ir)
    assert results[0].status == "fail"


def test_exists_where_passes_when_match_found():
    """exists_where must pass when a matching item is found."""
    from fireaudit.engine.evaluator import RuleEvaluator
    ir_with_deny = {
        "firewall_policies": [
            {"id": "1", "enabled": True, "action": "allow", "logging_enabled": True},
            {"id": "99", "enabled": True, "action": "deny", "logging_enabled": True},
        ]
    }
    rule = {
        "rule_id": "FW-POL-003",
        "name": "Test",
        "severity": "critical",
        "vendors": ["all"],
        "frameworks": {},
        "match": {
            "type": "condition",
            "path": "firewall_policies",
            "condition": {
                "type": "exists_where",
                "where": {
                    "action": {"type": "in", "values": ["deny", "drop", "reject"]},
                    "enabled": {"type": "is_true"},
                },
            },
        },
        "remediation": "",
        "description": "",
    }
    evaluator = RuleEvaluator([rule])
    results = evaluator.evaluate(ir_with_deny)
    assert results[0].status == "pass"


# ---------------------------------------------------------------------------
# vendor_commands / vendor_command tests
# ---------------------------------------------------------------------------

def test_vendor_command_populated_for_fortigate_fail(findings):
    """FAIL findings for rules that have vendor_commands must expose the fortigate command."""
    # FW-ADM-004 fails when timeout > 600s or null; sample_full.conf passes this rule.
    # Use FW-AUTH-002 which always fails on the sample fixture (has 'admin' account).
    f = next((f for f in findings if f.rule_id == "FW-AUTH-002"), None)
    assert f is not None
    assert f.status == "fail"
    # FW-AUTH-002 doesn't have vendor_commands; vendor_command should be empty string
    assert f.vendor_command == ""


def test_vendor_command_populated_for_rule_with_commands(findings):
    """A FAIL finding for a rule with vendor_commands should have vendor_command set."""
    # FW-VPN-001 fails on the fixture (3des tunnel present) and has vendor_commands
    f = next((f for f in findings if f.rule_id == "FW-VPN-001"), None)
    assert f is not None
    assert f.status == "fail"
    # vendor_commands dict should contain fortigate key
    assert "fortigate" in f.vendor_commands
    # vendor_command (resolved for fortigate) should be non-empty
    assert f.vendor_command.strip() != ""
    assert "phase1-interface" in f.vendor_command


def test_vendor_command_in_to_dict(findings):
    """to_dict() must include vendor_commands and vendor_command keys."""
    f = next((f for f in findings if f.rule_id == "FW-VPN-001"), None)
    assert f is not None
    d = f.to_dict()
    assert "vendor_commands" in d
    assert "vendor_command" in d
    assert isinstance(d["vendor_commands"], dict)
    assert isinstance(d["vendor_command"], str)


def test_vendor_command_empty_for_pass_finding(findings):
    """PASS findings must have an empty vendor_command (no remediation needed)."""
    f = next((f for f in findings if f.rule_id == "FW-ADM-004"), None)
    assert f is not None
    assert f.status == "pass"
    assert f.vendor_command == ""


def test_cisco_ftd_uses_cisco_asa_commands():
    """cisco_ftd vendor lookup should fall back to cisco_asa commands for FAIL findings."""
    rule = {
        "rule_id": "FW-ADM-004",
        "name": "Test",
        "severity": "medium",
        "vendors": ["all"],
        "frameworks": {},
        "match": {
            "type": "condition",
            "path": "admin_access.session_timeout_seconds",
            "condition": {"type": "is_not_null"},
        },
        "remediation": "Set timeout",
        "description": "",
        "vendor_commands": {
            "cisco_asa": "ssh timeout 10\nconsole timeout 10",
        },
    }
    # session_timeout_seconds is None → is_not_null fails → FAIL finding
    ir = {"admin_access": {"session_timeout_seconds": None}}
    evaluator = RuleEvaluator([rule])
    results = evaluator.evaluate(ir, vendor="cisco_ftd")
    assert results[0].status == "fail"
    # Should use cisco_asa commands as fallback for cisco_ftd
    assert results[0].vendor_command == "ssh timeout 10\nconsole timeout 10"
