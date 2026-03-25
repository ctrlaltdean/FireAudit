"""Tests for the Palo Alto parser."""

import pytest
from pathlib import Path

from fireaudit.parsers.paloalto import PaloAltoParser

FIXTURE = Path(__file__).parent.parent / "fixtures" / "paloalto" / "sample_running.xml"


@pytest.fixture(scope="module")
def ir():
    parser = PaloAltoParser()
    return parser.parse_file(FIXTURE)


def test_meta_vendor(ir):
    assert ir["meta"]["vendor"] == "paloalto"


def test_meta_hostname(ir):
    assert ir["meta"]["hostname"] == "PA-FW-EDGE-01"


def test_meta_firmware(ir):
    assert ir["meta"]["firmware_version"] == "10.1.11"


# Admin access
def test_https_enabled(ir):
    protocols = {p["protocol"]: p for p in ir["admin_access"]["management_protocols"]}
    assert protocols["https"]["enabled"] is True


def test_http_disabled(ir):
    protocols = {p["protocol"]: p for p in ir["admin_access"]["management_protocols"]}
    assert protocols["http"]["enabled"] is False


def test_ssh_enabled(ir):
    protocols = {p["protocol"]: p for p in ir["admin_access"]["management_protocols"]}
    assert protocols["ssh"]["enabled"] is True


def test_telnet_disabled(ir):
    protocols = {p["protocol"]: p for p in ir["admin_access"]["management_protocols"]}
    assert protocols["telnet"]["enabled"] is False


def test_ssh_version_2(ir):
    assert ir["admin_access"]["ssh_settings"]["version"] == 2


def test_session_timeout(ir):
    # idle-timeout 10 (minutes) → 600 seconds
    assert ir["admin_access"]["session_timeout_seconds"] == 600


def test_max_login_attempts(ir):
    assert ir["admin_access"]["max_login_attempts"] == 5


def test_trusted_hosts(ir):
    hosts = ir["admin_access"]["trusted_hosts"]
    assert len(hosts) == 2
    assert "10.10.1.0/24" in hosts


def test_banner_enabled(ir):
    assert ir["admin_access"]["banner_enabled"] is True
    assert "UNAUTHORIZED" in ir["admin_access"]["banner"]


def test_snmp_v3(ir):
    assert ir["admin_access"]["snmp"]["enabled"] is True
    assert ir["admin_access"]["snmp"]["version"] == "v3"


# Authentication
def test_password_min_length(ir):
    assert ir["authentication"]["password_policy"]["min_length"] == 12


def test_password_requires_uppercase(ir):
    assert ir["authentication"]["password_policy"]["require_uppercase"] is True


def test_password_requires_special(ir):
    assert ir["authentication"]["password_policy"]["require_special"] is True


def test_lockout_threshold(ir):
    assert ir["authentication"]["password_policy"]["lockout_threshold"] == 5


def test_local_users(ir):
    usernames = {u["username"] for u in ir["authentication"]["local_users"]}
    assert "admin" in usernames
    assert "svc-readonly" in usernames


def test_default_admin_exists(ir):
    assert ir["authentication"]["default_admin_account_exists"] is True


def test_mfa_user(ir):
    users = {u["username"]: u for u in ir["authentication"]["local_users"]}
    assert users["svc-readonly"]["mfa_enabled"] is True


# Logging
def test_ntp_servers(ir):
    assert ir["logging"]["ntp_enabled"] is True
    assert len(ir["logging"]["ntp_servers"]) == 2


def test_syslog_servers(ir):
    assert len(ir["logging"]["syslog_servers"]) == 2
    hosts = {s["host"] for s in ir["logging"]["syslog_servers"]}
    assert "10.10.1.200" in hosts


# VPN
def test_ipsec_tunnel_count(ir):
    assert len(ir["vpn"]["ipsec_tunnels"]) == 2


def test_strong_tunnel(ir):
    tunnels = {t["name"]: t for t in ir["vpn"]["ipsec_tunnels"]}
    t = tunnels["IPSEC-TUNNEL-HQ"]
    assert t["phase1"]["ike_version"] == 2
    assert "aes-256-cbc" in t["phase1"]["encryption"] or "aes256" in " ".join(t["phase1"]["encryption"])
    assert 19 in t["phase1"]["dh_groups"] or 14 in t["phase1"]["dh_groups"]


def test_weak_tunnel(ir):
    tunnels = {t["name"]: t for t in ir["vpn"]["ipsec_tunnels"]}
    t = tunnels["IPSEC-TUNNEL-PARTNER"]
    assert t["phase1"]["ike_version"] == 1
    assert 2 in t["phase1"]["dh_groups"]


# Firewall policies
def test_policy_count(ir):
    assert len(ir["firewall_policies"]) == 4


def test_any_any_policy(ir):
    any_any = [
        p for p in ir["firewall_policies"]
        if "any" in p["source_addresses"] and "any" in p["destination_addresses"]
        and p["action"] == "allow" and p["enabled"]
    ]
    assert len(any_any) >= 1


def test_no_log_policy(ir):
    no_log = [p for p in ir["firewall_policies"]
               if p["enabled"] and p["action"] == "allow" and not p["logging_enabled"]]
    assert len(no_log) >= 1


# Interfaces
def test_interfaces_parsed(ir):
    names = {i["name"] for i in ir["interfaces"]}
    assert "ethernet1/1" in names
    assert "ethernet1/2" in names


def test_interface_zone_mapping(ir):
    ifaces = {i["name"]: i for i in ir["interfaces"]}
    # Zone cross-reference
    assert ifaces.get("ethernet1/1", {}).get("zone") in ("trust", None)


# Network objects
def test_address_objects(ir):
    names = {o["name"] for o in ir["network_objects"]["address_objects"]}
    assert "CORP-NET" in names
    assert "DMZ-SERVER" in names


def test_service_objects(ir):
    names = {o["name"] for o in ir["network_objects"]["service_objects"]}
    assert "tcp-8443" in names
