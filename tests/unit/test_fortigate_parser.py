"""Tests for the FortiGate parser."""

import pytest
from pathlib import Path

from fireaudit.parsers.fortigate import FortiGateParser

FIXTURE = Path(__file__).parent.parent / "fixtures" / "fortigate" / "sample_full.conf"


@pytest.fixture(scope="module")
def ir():
    parser = FortiGateParser()
    return parser.parse_file(FIXTURE)


def test_meta_vendor(ir):
    assert ir["meta"]["vendor"] == "fortigate"


def test_meta_hostname(ir):
    assert ir["meta"]["hostname"] == "FW-BRANCH-01"


def test_admin_http_disabled(ir):
    protocols = {p["protocol"]: p for p in ir["admin_access"]["management_protocols"]}
    assert protocols["http"]["enabled"] is False


def test_admin_telnet_disabled(ir):
    protocols = {p["protocol"]: p for p in ir["admin_access"]["management_protocols"]}
    assert protocols["telnet"]["enabled"] is False


def test_admin_session_timeout(ir):
    # admintimeout 5 minutes = 300 seconds
    assert ir["admin_access"]["session_timeout_seconds"] == 300


def test_trusted_hosts_populated(ir):
    assert len(ir["admin_access"]["trusted_hosts"]) > 0


def test_banner_enabled(ir):
    assert ir["admin_access"]["banner_enabled"] is True


def test_password_min_length(ir):
    assert ir["authentication"]["password_policy"]["min_length"] == 12


def test_password_max_age(ir):
    assert ir["authentication"]["password_policy"]["max_age_days"] == 90


def test_local_users(ir):
    usernames = {u["username"] for u in ir["authentication"]["local_users"]}
    assert "admin" in usernames
    assert "svc-audit" in usernames


def test_default_admin_exists(ir):
    assert ir["authentication"]["default_admin_account_exists"] is True


def test_mfa_user(ir):
    users = {u["username"]: u for u in ir["authentication"]["local_users"]}
    assert users["svc-audit"]["mfa_enabled"] is True


def test_syslog_servers(ir):
    assert len(ir["logging"]["syslog_servers"]) == 2
    hosts = {s["host"] for s in ir["logging"]["syslog_servers"]}
    assert "10.10.1.200" in hosts


def test_ntp_enabled(ir):
    assert ir["logging"]["ntp_enabled"] is True
    assert len(ir["logging"]["ntp_servers"]) > 0


def test_snmp_enabled(ir):
    assert ir["admin_access"]["snmp"]["enabled"] is True
    assert "public" in ir["admin_access"]["snmp"]["community_strings"]


def test_radius_configured(ir):
    assert ir["authentication"]["remote_auth"]["radius_enabled"] is True


def test_ipsec_tunnels_count(ir):
    assert len(ir["vpn"]["ipsec_tunnels"]) == 2


def test_strong_tunnel_phase1(ir):
    tunnels = {t["name"]: t for t in ir["vpn"]["ipsec_tunnels"]}
    t = tunnels["VPN-HEADOFFICE"]
    assert t["phase1"]["ike_version"] == 2
    assert 19 in t["phase1"]["dh_groups"] or 14 in t["phase1"]["dh_groups"]


def test_weak_tunnel_phase1(ir):
    tunnels = {t["name"]: t for t in ir["vpn"]["ipsec_tunnels"]}
    t = tunnels["VPN-PARTNER-LEGACY"]
    assert t["phase1"]["ike_version"] == 1
    assert any(g in t["phase1"]["dh_groups"] for g in [2, 5])


def test_ssl_vpn_enabled(ir):
    assert ir["vpn"]["ssl_vpn"]["enabled"] is True


def test_firewall_policies_count(ir):
    assert len(ir["firewall_policies"]) == 4


def test_any_any_policy_detected(ir):
    any_any = [
        p for p in ir["firewall_policies"]
        if "all" in p["source_addresses"] and "all" in p["destination_addresses"]
        and p["action"] == "allow" and p["enabled"]
    ]
    assert len(any_any) >= 1


def test_policy_without_logging(ir):
    no_log = [p for p in ir["firewall_policies"] if p["enabled"] and p["action"] == "allow" and not p["logging_enabled"]]
    assert len(no_log) >= 1  # policy 4 has logtraffic disable


def test_interfaces_parsed(ir):
    names = {i["name"] for i in ir["interfaces"]}
    assert "port1" in names
    assert "port2" in names


def test_network_objects(ir):
    obj_names = {o["name"] for o in ir["network_objects"]["address_objects"]}
    assert "all" in obj_names
    assert "CORP-NET" in obj_names
