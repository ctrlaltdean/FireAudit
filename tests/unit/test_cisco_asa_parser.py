"""Tests for the Cisco ASA parser."""

import pytest
from pathlib import Path

from fireaudit.parsers.cisco_asa import CiscoASAParser

FIXTURE = Path(__file__).parent.parent / "fixtures" / "cisco_asa" / "sample_running.conf"


@pytest.fixture(scope="module")
def ir():
    parser = CiscoASAParser()
    return parser.parse_file(FIXTURE)


def test_meta_vendor(ir):
    assert ir["meta"]["vendor"] == "cisco_asa"


def test_meta_hostname(ir):
    assert ir["meta"]["hostname"] == "ASA-EDGE-01"


def test_meta_firmware(ir):
    assert ir["meta"]["firmware_version"] == "9.16(4)"


# Admin access
def test_ssh_enabled(ir):
    protocols = {p["protocol"]: p for p in ir["admin_access"]["management_protocols"]}
    assert protocols["ssh"]["enabled"] is True


def test_ssh_version_2(ir):
    assert ir["admin_access"]["ssh_settings"]["version"] == 2


def test_telnet_disabled(ir):
    protocols = {p["protocol"]: p for p in ir["admin_access"]["management_protocols"]}
    # No 'telnet <ip> ...' access lines in fixture (only timeout) → not enabled
    assert protocols["telnet"]["enabled"] is False


def test_https_enabled(ir):
    protocols = {p["protocol"]: p for p in ir["admin_access"]["management_protocols"]}
    assert protocols["https"]["enabled"] is True


def test_session_timeout(ir):
    # ssh timeout 10 → 600s
    assert ir["admin_access"]["session_timeout_seconds"] == 600


def test_max_login_attempts(ir):
    assert ir["admin_access"]["max_login_attempts"] == 5


def test_trusted_hosts(ir):
    # ssh 10.10.1.0 255.255.255.0 → trusted host
    assert len(ir["admin_access"]["trusted_hosts"]) > 0
    assert any("10.10.1" in h for h in ir["admin_access"]["trusted_hosts"])


def test_banner_enabled(ir):
    assert ir["admin_access"]["banner_enabled"] is True
    assert "UNAUTHORIZED" in (ir["admin_access"]["banner"] or "")


def test_snmp_enabled(ir):
    # No snmp lines in fixture → not enabled
    assert ir["admin_access"]["snmp"]["enabled"] is False


def test_tls_version(ir):
    assert "TLSv1.2" in ir["admin_access"]["https_settings"]["tls_versions"]


# Authentication
def test_local_users(ir):
    names = {u["username"] for u in ir["authentication"]["local_users"]}
    assert "admin" in names
    assert "svc-readonly" in names


def test_default_admin_exists(ir):
    assert ir["authentication"]["default_admin_account_exists"] is True


def test_password_min_length(ir):
    assert ir["authentication"]["password_policy"]["min_length"] == 14


def test_password_max_age(ir):
    assert ir["authentication"]["password_policy"]["max_age_days"] == 90


def test_radius_configured(ir):
    assert ir["authentication"]["remote_auth"]["radius_enabled"] is True


# Logging
def test_syslog_servers(ir):
    assert len(ir["logging"]["syslog_servers"]) == 2
    hosts = {s["host"] for s in ir["logging"]["syslog_servers"]}
    assert "10.10.1.200" in hosts


def test_ntp_servers(ir):
    assert ir["logging"]["ntp_enabled"] is True
    assert len(ir["logging"]["ntp_servers"]) >= 2


# VPN — crypto maps
def test_ipsec_tunnels(ir):
    assert len(ir["vpn"]["ipsec_tunnels"]) >= 1


def test_strong_tunnel_peer(ir):
    peers = {t["remote_gateway"] for t in ir["vpn"]["ipsec_tunnels"]}
    assert "198.51.100.10" in peers


def test_ikev2_tunnel(ir):
    tunnels = [t for t in ir["vpn"]["ipsec_tunnels"] if t["remote_gateway"] == "198.51.100.10"]
    assert len(tunnels) >= 1
    assert tunnels[0]["phase1"]["ike_version"] == 2


def test_ssl_vpn_enabled(ir):
    assert ir["vpn"]["ssl_vpn"]["enabled"] is True


# Firewall policies
def test_firewall_policies_parsed(ir):
    assert len(ir["firewall_policies"]) >= 2


def test_any_any_unlogged(ir):
    # INSIDE_OUT has 'permit ip any any' without 'log'
    no_log_allow = [p for p in ir["firewall_policies"]
                     if p["action"] == "allow" and not p["logging_enabled"]]
    assert len(no_log_allow) >= 1


def test_logged_policy(ir):
    # OUTSIDE_IN has 'deny ip any any log'
    logged = [p for p in ir["firewall_policies"] if p["logging_enabled"]]
    assert len(logged) >= 1


# Interfaces
def test_interfaces_parsed(ir):
    names = {i["name"] for i in ir["interfaces"]}
    assert "GigabitEthernet0/0" in names
    assert "GigabitEthernet0/1" in names


def test_interface_nameif(ir):
    ifaces = {i["name"]: i for i in ir["interfaces"]}
    assert ifaces["GigabitEthernet0/0"]["zone"] == "outside"
    assert ifaces["GigabitEthernet0/1"]["zone"] == "inside"


def test_interface_ip(ir):
    ifaces = {i["name"]: i for i in ir["interfaces"]}
    assert ifaces["GigabitEthernet0/1"]["ip_address"] == "10.10.1.1"


# Network objects
def test_address_objects(ir):
    names = {o["name"] for o in ir["network_objects"]["address_objects"]}
    assert "CORP-NET" in names
    assert "DMZ-SERVER" in names


def test_service_objects(ir):
    names = {o["name"] for o in ir["network_objects"]["service_objects"]}
    assert "HTTPS" in names or "tcp-443" in names or len(names) > 0
