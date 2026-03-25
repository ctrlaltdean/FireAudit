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
    assert report["summary"]["pass"] + report["summary"]["fail"] + report["summary"].get("error", 0) == len(findings)
