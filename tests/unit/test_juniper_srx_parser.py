"""Unit tests for the Juniper SRX JunOS hierarchical configuration parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from fireaudit.parsers.juniper_srx import JuniperSRXParser

FIXTURE = Path(__file__).parent.parent / "fixtures" / "juniper_srx" / "sample_config.conf"


@pytest.fixture(scope="module")
def ir():
    parser = JuniperSRXParser()
    return parser.parse_file(FIXTURE)


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------

class TestMeta:
    def test_vendor(self, ir):
        assert ir["meta"]["vendor"] == "juniper_srx"

    def test_hostname(self, ir):
        assert ir["meta"]["hostname"] == "SRX-BRANCH-01"

    def test_firmware_version(self, ir):
        assert ir["meta"]["firmware_version"] is not None
        assert "22.4" in ir["meta"]["firmware_version"]


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
        # Fixture intentionally enables telnet — triggers FW-ADM-002
        assert self._protos["telnet"]["enabled"] is True

    def test_https_enabled(self):
        assert self._protos["https"]["enabled"] is True


class TestSSH:
    def test_ssh_version(self, ir):
        assert ir["admin_access"]["ssh_settings"]["version"] == 2

    def test_ssh_enabled(self, ir):
        assert ir["admin_access"]["ssh_settings"]["enabled"] is True


class TestSNMP:
    def test_snmp_enabled(self, ir):
        # Fixture has SNMPv2c community — triggers FW-ADM-007
        assert ir["admin_access"]["snmp"]["enabled"] is True

    def test_snmp_version_v2c(self, ir):
        assert ir["admin_access"]["snmp"]["version"] in ("v2c", "v1v2c", "2c")

    def test_snmp_community_present(self, ir):
        assert len(ir["admin_access"]["snmp"]["community_strings"]) >= 1


class TestSessionBanner:
    def test_banner_not_set(self, ir):
        # Fixture omits login message — triggers FW-ADM-006
        assert not ir["admin_access"]["banner_enabled"]

    def test_max_login_attempts(self, ir):
        # Fixture sets tries-before-disconnect 5
        assert ir["admin_access"]["max_login_attempts"] == 5


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
        assert ir["authentication"]["default_admin_account_exists"] is True


# ---------------------------------------------------------------------------
# Logging / NTP
# ---------------------------------------------------------------------------

class TestLogging:
    def test_syslog_servers_configured(self, ir):
        servers = ir["logging"]["syslog_servers"]
        assert len(servers) >= 1

    def test_syslog_server_address(self, ir):
        addrs = [s.get("address") or s.get("host") for s in ir["logging"]["syslog_servers"]]
        assert "10.0.0.100" in addrs

    def test_ntp_servers_present(self, ir):
        assert len(ir["logging"]["ntp_servers"]) >= 2

    def test_ntp_enabled(self, ir):
        assert ir["logging"]["ntp_enabled"] is True


# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------

class TestInterfaces:
    def test_interfaces_parsed(self, ir):
        assert len(ir["interfaces"]) >= 3

    def test_wan_interface_role(self, ir):
        # ge-0/0/0 is in zone untrust — should infer WAN role
        roles = [i.get("role") for i in ir["interfaces"]]
        assert "wan" in roles


# ---------------------------------------------------------------------------
# Firewall policies
# ---------------------------------------------------------------------------

class TestFirewallPolicies:
    def test_policies_parsed(self, ir):
        assert len(ir["firewall_policies"]) >= 2

    def test_deny_policy_exists(self, ir):
        actions = [p.get("action") for p in ir["firewall_policies"]]
        assert "deny" in actions

    def test_allow_policy_exists(self, ir):
        actions = [p.get("action") for p in ir["firewall_policies"]]
        assert "allow" in actions

    def test_any_any_allow_without_logging(self, ir):
        # Fixture has allow-outbound-any with no logging — triggers FW-POL-001/002
        unlogged = [
            p for p in ir["firewall_policies"]
            if p.get("action") == "allow" and not p.get("log")
        ]
        assert len(unlogged) >= 1


# ---------------------------------------------------------------------------
# VPN / IPsec
# ---------------------------------------------------------------------------

class TestVPN:
    def test_ipsec_tunnels_present(self, ir):
        assert len(ir["vpn"]["ipsec_tunnels"]) >= 1

    def test_weak_encryption_present(self, ir):
        # Fixture has 3DES on ipsec-prop-weak — triggers FW-VPN-001
        all_enc = [t.get("phase2", {}).get("encryption") or t.get("encryption")
                   for t in ir["vpn"]["ipsec_tunnels"]]
        assert any("3des" in str(e).lower() for e in all_enc if e)

    def test_aggressive_mode_present(self, ir):
        # Fixture has ike-pol-aggressive — triggers FW-VPN-008
        agg = [t for t in ir["vpn"]["ipsec_tunnels"]
               if t.get("phase1", {}).get("aggressive_mode") is True]
        assert len(agg) >= 1

    def test_weak_dh_group_present(self, ir):
        # Fixture has dh-group group2 — triggers FW-VPN-003
        # dh_groups is a list inside phase1
        all_groups = []
        for t in ir["vpn"]["ipsec_tunnels"]:
            all_groups.extend(t.get("phase1", {}).get("dh_groups") or [])
        assert any(g in (2, "2", "group2") for g in all_groups)

    def test_psk_auth_present(self, ir):
        # Fixture uses pre-shared-keys — triggers FW-VPN-013
        # auth_method is a top-level key on the tunnel dict
        auth_methods = [t.get("auth_method") for t in ir["vpn"]["ipsec_tunnels"]]
        assert any("psk" in str(m).lower() or "pre" in str(m).lower()
                   for m in auth_methods if m)


# ---------------------------------------------------------------------------
# Smoke: rule engine round-trip
# ---------------------------------------------------------------------------

class TestRuleEngine:
    def test_evaluates_without_error(self, ir):
        from fireaudit.engine.loader import RuleLoader
        from fireaudit.engine.evaluator import RuleEvaluator

        rules_path = Path(__file__).parent.parent.parent / "rules"
        loader = RuleLoader(rules_path)
        rules = loader.load_for_vendor("juniper_srx")
        assert len(rules) > 0

        evaluator = RuleEvaluator(rules)
        findings = evaluator.evaluate(ir, vendor="juniper_srx")
        assert len(findings) > 0

    def test_known_fails(self, ir):
        from fireaudit.engine.loader import RuleLoader
        from fireaudit.engine.evaluator import RuleEvaluator

        rules_path = Path(__file__).parent.parent.parent / "rules"
        loader = RuleLoader(rules_path)
        rules = loader.load_for_vendor("juniper_srx")
        evaluator = RuleEvaluator(rules)
        findings = evaluator.evaluate(ir, vendor="juniper_srx")

        fail_ids = {f.rule_id for f in findings if f.status == "fail"}
        # Fixture has telnet enabled
        assert "FW-ADM-002" in fail_ids
        # Fixture has SNMPv2c
        assert "FW-ADM-007" in fail_ids
        # Fixture has no banner
        assert "FW-ADM-006" in fail_ids
        # Fixture has 3DES-CBC encryption (weak)
        assert "FW-VPN-001" in fail_ids
        # Fixture has aggressive mode
        assert "FW-VPN-008" in fail_ids
        # Fixture has MD5/SHA-1 on phase2
        assert "FW-VPN-005" in fail_ids or "FW-VPN-006" in fail_ids

    def test_posture_score_present(self, ir):
        from fireaudit.engine.loader import RuleLoader
        from fireaudit.engine.evaluator import RuleEvaluator, build_report

        rules_path = Path(__file__).parent.parent.parent / "rules"
        loader = RuleLoader(rules_path)
        rules = loader.load_for_vendor("juniper_srx")
        evaluator = RuleEvaluator(rules)
        findings = evaluator.evaluate(ir, vendor="juniper_srx")
        report = build_report(ir, findings)

        assert "posture_score" in report
        assert 0 <= report["posture_score"]["score"] <= 100
