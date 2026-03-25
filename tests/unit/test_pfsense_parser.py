"""Tests for the pfSense parser."""

import pytest
from pathlib import Path

from fireaudit.parsers.pfsense import PfSenseParser

FIXTURE = Path(__file__).parent.parent / "fixtures" / "pfsense" / "sample_config.xml"


@pytest.fixture(scope="module")
def ir():
    parser = PfSenseParser()
    return parser.parse_file(FIXTURE)


def test_meta_vendor(ir):
    assert ir["meta"]["vendor"] == "pfsense"


def test_meta_hostname(ir):
    assert "pfsense-branch" in ir["meta"]["hostname"]


def test_meta_firmware(ir):
    assert ir["meta"]["firmware_version"] == "21.7.3"


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


def test_session_timeout(ir):
    assert ir["admin_access"]["session_timeout_seconds"] == 10


def test_login_protection(ir):
    assert ir["admin_access"]["max_login_attempts"] is not None


# Authentication
def test_local_users(ir):
    names = {u["username"] for u in ir["authentication"]["local_users"]}
    assert "admin" in names
    assert "svc-monitor" in names


def test_default_admin_exists(ir):
    assert ir["authentication"]["default_admin_account_exists"] is True


def test_mfa_user(ir):
    users = {u["username"]: u for u in ir["authentication"]["local_users"]}
    assert users["svc-monitor"]["mfa_enabled"] is True


def test_bcrypt_hashing(ir):
    users = {u["username"]: u for u in ir["authentication"]["local_users"]}
    assert users["admin"]["password_hash_algorithm"] == "bcrypt"


def test_radius_configured(ir):
    assert ir["authentication"]["remote_auth"]["radius_enabled"] is True
    assert len(ir["authentication"]["remote_auth"]["servers"]) > 0


# Logging
def test_ntp_configured(ir):
    assert ir["logging"]["ntp_enabled"] is True
    assert len(ir["logging"]["ntp_servers"]) == 2


def test_syslog_servers(ir):
    assert len(ir["logging"]["syslog_servers"]) == 2
    hosts = {s["host"] for s in ir["logging"]["syslog_servers"]}
    assert "10.10.1.200" in hosts


def test_log_traffic(ir):
    assert ir["logging"]["log_traffic"] is True


def test_log_auth(ir):
    assert ir["logging"]["log_authentication"] is True


# VPN
def test_ipsec_tunnels(ir):
    assert len(ir["vpn"]["ipsec_tunnels"]) == 2


def test_strong_tunnel(ir):
    tunnels = {t["name"]: t for t in ir["vpn"]["ipsec_tunnels"]}
    t = tunnels["HQ-Tunnel"]
    assert t["phase1"]["ike_version"] == 2
    assert 14 in t["phase1"]["dh_groups"]
    assert "aes256" in " ".join(t["phase1"]["encryption"]).lower() or "aes" in t["phase1"]["encryption"][0]


def test_weak_tunnel(ir):
    tunnels = {t["name"]: t for t in ir["vpn"]["ipsec_tunnels"]}
    t = tunnels["Partner-Legacy-Tunnel"]
    assert t["phase1"]["ike_version"] == 1
    assert 2 in t["phase1"]["dh_groups"]
    assert "3des" in t["phase1"]["encryption"][0].lower()


def test_openvpn_ssl_vpn(ir):
    assert ir["vpn"]["ssl_vpn"]["enabled"] is True
    assert ir["vpn"]["ssl_vpn"]["client_certificate_required"] is True


# Firewall policies
def test_policy_count(ir):
    assert len(ir["firewall_policies"]) == 4


def test_any_any_policy(ir):
    any_any = [
        p for p in ir["firewall_policies"]
        if "all" in p["source_addresses"] and "all" in p["destination_addresses"]
        and p["action"] == "allow" and p["enabled"]
    ]
    assert len(any_any) >= 1


def test_no_log_policy(ir):
    no_log = [p for p in ir["firewall_policies"]
               if p["enabled"] and p["action"] == "allow" and not p["logging_enabled"]]
    assert len(no_log) >= 1


# Interfaces
def test_interfaces(ir):
    names = {i["name"] for i in ir["interfaces"]}
    assert "em0" in names
    assert "em1" in names


def test_interface_ip(ir):
    ifaces = {i["name"]: i for i in ir["interfaces"]}
    assert ifaces["em1"]["ip_address"] == "10.10.1.1"
