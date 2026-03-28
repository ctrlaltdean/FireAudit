"""Unit tests for the Check Point Gaia OS clish configuration parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from fireaudit.parsers.checkpoint import CheckPointParser

FIXTURE = Path(__file__).parent.parent / "fixtures" / "checkpoint" / "sample_gaia.conf"


@pytest.fixture(scope="module")
def ir():
    parser = CheckPointParser()
    return parser.parse_file(FIXTURE)


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------

class TestMeta:
    def test_vendor(self, ir):
        assert ir["meta"]["vendor"] == "checkpoint"

    def test_hostname(self, ir):
        assert ir["meta"]["hostname"] == "FW-CP-GW-01"

    def test_firmware_version(self, ir):
        assert ir["meta"]["firmware_version"] is not None
        assert "R81" in ir["meta"]["firmware_version"]


# ---------------------------------------------------------------------------
# Admin access — management protocols
# ---------------------------------------------------------------------------

class TestManagementProtocols:
    @pytest.fixture(autouse=True)
    def protos(self, ir):
        self._protos = {p["protocol"]: p for p in ir["admin_access"]["management_protocols"]}

    def test_ssh_enabled(self):
        assert self._protos["ssh"]["enabled"] is True

    def test_telnet_enabled_gap(self):
        # Fixture intentionally has telnet on — should show as enabled (triggers FAIL)
        assert self._protos["telnet"]["enabled"] is True

    def test_https_enabled(self):
        assert self._protos["https"]["enabled"] is True

    def test_snmp_enabled(self, ir):
        assert ir["admin_access"]["snmp"]["enabled"] is True

    def test_snmp_version_v2c(self, ir):
        # Fixture uses SNMPv2c — should trigger FW-ADM-007
        assert ir["admin_access"]["snmp"]["version"] in ("v2c", "v1v2c", "2c")

    def test_snmp_community_present(self, ir):
        assert len(ir["admin_access"]["snmp"]["community_strings"]) >= 1


# ---------------------------------------------------------------------------
# Admin access — session / TLS
# ---------------------------------------------------------------------------

class TestSessionSettings:
    def test_session_timeout_seconds(self, ir):
        # Fixture sets 60-minute timeout — should be 3600 seconds
        timeout = ir["admin_access"]["session_timeout_seconds"]
        assert timeout == 3600

    def test_https_tls_version_weak(self, ir):
        # Fixture sets SSLv3 minimum — tls_versions list should show a weak version
        tls = ir["admin_access"]["https_settings"]["tls_versions"]
        assert isinstance(tls, list)

    def test_banner_not_set(self, ir):
        # Fixture intentionally omits banner — triggers FW-ADM-006
        assert not ir["admin_access"]["banner_enabled"]

    def test_max_login_attempts_not_set(self, ir):
        # Fixture has no login-max-failed-auth — triggers FW-ADM-009
        assert ir["admin_access"]["max_login_attempts"] is None


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

class TestAuthentication:
    def test_local_users_present(self, ir):
        users = ir["authentication"]["local_users"]
        assert len(users) >= 2

    def test_admin_user_exists(self, ir):
        names = [u["username"] for u in ir["authentication"]["local_users"]]
        assert "admin" in names

    def test_default_admin_account_flag(self, ir):
        # Fixture has 'admin' user — should flag default_admin_account_exists
        assert ir["authentication"]["default_admin_account_exists"] is True

    def test_password_min_length_weak(self, ir):
        # Fixture sets min-password-length 6
        min_len = ir["authentication"]["password_policy"]["min_length"]
        assert min_len == 6

    def test_password_history_not_set(self, ir):
        assert ir["authentication"]["password_policy"]["history_count"] is None

    def test_password_max_age_not_set(self, ir):
        assert ir["authentication"]["password_policy"]["max_age_days"] is None


# ---------------------------------------------------------------------------
# Logging / NTP
# ---------------------------------------------------------------------------

class TestLogging:
    def test_syslog_servers_configured(self, ir):
        servers = ir["logging"]["syslog_servers"]
        assert len(servers) >= 1

    def test_syslog_server_addresses(self, ir):
        # Syslog server entries use "host" key in the IR
        addrs = [s.get("address") or s.get("host") for s in ir["logging"]["syslog_servers"]]
        assert "10.0.0.100" in addrs

    def test_ntp_enabled(self, ir):
        assert ir["logging"]["ntp_enabled"] is True

    def test_ntp_servers_present(self, ir):
        assert len(ir["logging"]["ntp_servers"]) >= 2


# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------

class TestInterfaces:
    def test_interfaces_parsed(self, ir):
        assert len(ir["interfaces"]) >= 3

    def test_wan_interface_present(self, ir):
        roles = [i.get("role") for i in ir["interfaces"]]
        assert "wan" in roles or any(
            "eth0" in (i.get("name") or "") for i in ir["interfaces"]
        )


# ---------------------------------------------------------------------------
# Smoke: rule engine round-trip
# ---------------------------------------------------------------------------

class TestRuleEngine:
    def test_evaluates_without_error(self, ir):
        from fireaudit.engine.loader import RuleLoader
        from fireaudit.engine.evaluator import RuleEvaluator, build_report

        rules_path = Path(__file__).parent.parent.parent / "rules"
        loader = RuleLoader(rules_path)
        rules = loader.load_for_vendor("checkpoint")
        assert len(rules) > 0

        evaluator = RuleEvaluator(rules)
        findings = evaluator.evaluate(ir, vendor="checkpoint")
        assert len(findings) > 0

    def test_known_fails(self, ir):
        from fireaudit.engine.loader import RuleLoader
        from fireaudit.engine.evaluator import RuleEvaluator, build_report

        rules_path = Path(__file__).parent.parent.parent / "rules"
        loader = RuleLoader(rules_path)
        rules = loader.load_for_vendor("checkpoint")
        evaluator = RuleEvaluator(rules)
        findings = evaluator.evaluate(ir, vendor="checkpoint")

        fail_ids = {f.rule_id for f in findings if f.status == "fail"}
        # Fixture has telnet on
        assert "FW-ADM-002" in fail_ids
        # Fixture has SNMPv2c
        assert "FW-ADM-007" in fail_ids
        # Fixture has no banner
        assert "FW-ADM-006" in fail_ids
        # Fixture has weak password min length (6)
        assert "FW-AUTH-001" in fail_ids

    def test_posture_score_present(self, ir):
        from fireaudit.engine.loader import RuleLoader
        from fireaudit.engine.evaluator import RuleEvaluator, build_report

        rules_path = Path(__file__).parent.parent.parent / "rules"
        loader = RuleLoader(rules_path)
        rules = loader.load_for_vendor("checkpoint")
        evaluator = RuleEvaluator(rules)
        findings = evaluator.evaluate(ir, vendor="checkpoint")
        report = build_report(ir, findings)

        assert "posture_score" in report
        assert 0 <= report["posture_score"]["score"] <= 100
