"""Unit tests for the Sophos XG / SFOS XML configuration parser."""

from __future__ import annotations

import pytest
from pathlib import Path

from fireaudit.parsers.sophos_xg import SophosXGParser

FIXTURE = Path(__file__).parent.parent / "fixtures" / "sophos_xg" / "sample_backup.xml"


@pytest.fixture(scope="module")
def ir():
    parser = SophosXGParser()
    return parser.parse_file(FIXTURE)


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------

class TestMeta:
    def test_vendor(self, ir):
        assert ir["meta"]["vendor"] == "sophos_xg"

    def test_hostname(self, ir):
        assert ir["meta"]["hostname"] == "SOPHOS-XG-01"

    def test_model(self, ir):
        assert ir["meta"]["model"] == "XG 135"

    def test_firmware_version(self, ir):
        assert ir["meta"]["firmware_version"] is not None
        assert "SFOS" in ir["meta"]["firmware_version"]


# ---------------------------------------------------------------------------
# Admin access
# ---------------------------------------------------------------------------

class TestAdminAccess:
    def test_session_timeout_seconds(self, ir):
        # Fixture: 10 minutes -> 600 seconds
        assert ir["admin_access"]["session_timeout_seconds"] == 600

    def test_max_login_attempts(self, ir):
        assert ir["admin_access"]["max_login_attempts"] == 5

    def test_https_enabled(self, ir):
        assert ir["admin_access"]["https_settings"]["enabled"] is True

    def test_http_disabled(self, ir):
        protos = {p["protocol"]: p for p in ir["admin_access"]["management_protocols"]}
        assert protos["http"]["enabled"] is False

    def test_ssh_enabled(self, ir):
        protos = {p["protocol"]: p for p in ir["admin_access"]["management_protocols"]}
        assert protos["ssh"]["enabled"] is True

    def test_telnet_disabled(self, ir):
        protos = {p["protocol"]: p for p in ir["admin_access"]["management_protocols"]}
        assert protos["telnet"]["enabled"] is False

    def test_banner_present(self, ir):
        assert ir["admin_access"]["banner_enabled"] is True
        assert ir["admin_access"]["banner"] is not None

    def test_trusted_hosts(self, ir):
        hosts = ir["admin_access"]["trusted_hosts"]
        assert len(hosts) >= 2
        assert "10.10.1.0/24" in hosts

    def test_snmp_v3(self, ir):
        snmp = ir["admin_access"]["snmp"]
        assert snmp["enabled"] is True
        assert "3" in (snmp["version"] or "")

    def test_snmp_community(self, ir):
        snmp = ir["admin_access"]["snmp"]
        assert snmp.get("community_strings") is not None
        assert len(snmp["community_strings"]) == 1

    def test_tls_min_version(self, ir):
        tls_versions = ir["admin_access"]["https_settings"].get("tls_versions")
        assert tls_versions is not None
        assert any("1.2" in v for v in tls_versions)


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

class TestAuthentication:
    def test_password_min_length(self, ir):
        assert ir["authentication"]["password_policy"]["min_length"] == 12

    def test_password_max_age(self, ir):
        assert ir["authentication"]["password_policy"]["max_age_days"] == 90

    def test_password_history(self, ir):
        assert ir["authentication"]["password_policy"]["history_count"] == 5

    def test_default_admin_exists(self, ir):
        assert ir["authentication"]["default_admin_account_exists"] is True
        assert ir["authentication"]["default_admin_renamed"] is False

    def test_local_users_count(self, ir):
        assert len(ir["authentication"]["local_users"]) == 2

    def test_admin_user_no_mfa(self, ir):
        admin = next(u for u in ir["authentication"]["local_users"] if u["username"] == "admin")
        assert admin["mfa_enabled"] is False
        assert admin["privilege_level"] == "administrator"

    def test_svc_user_has_mfa(self, ir):
        svc = next(u for u in ir["authentication"]["local_users"] if u["username"] == "svc-monitor")
        assert svc["mfa_enabled"] is True

    def test_radius_enabled(self, ir):
        assert ir["authentication"]["remote_auth"]["radius_enabled"] is True
        servers = ir["authentication"]["remote_auth"]["servers"]
        radius = next((s for s in servers if s["type"] == "radius"), None)
        assert radius is not None
        assert radius["host"] == "10.10.1.150"
        assert radius["port"] == 1812


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

class TestLogging:
    def test_syslog_servers_count(self, ir):
        assert len(ir["logging"]["syslog_servers"]) == 2

    def test_syslog_primary(self, ir):
        servers = {s["host"]: s for s in ir["logging"]["syslog_servers"]}
        assert "10.10.1.200" in servers
        assert servers["10.10.1.200"]["port"] == 514
        assert servers["10.10.1.200"]["protocol"] == "udp"

    def test_syslog_secondary_tcp(self, ir):
        servers = {s["host"]: s for s in ir["logging"]["syslog_servers"]}
        assert "10.10.1.201" in servers
        assert servers["10.10.1.201"]["port"] == 6514
        assert servers["10.10.1.201"]["protocol"] == "tcp"

    def test_ntp_enabled(self, ir):
        assert ir["logging"]["ntp_enabled"] is True

    def test_ntp_servers(self, ir):
        servers = ir["logging"]["ntp_servers"]
        assert len(servers) >= 2
        assert "pool.ntp.org" in servers


# ---------------------------------------------------------------------------
# Firewall policies
# ---------------------------------------------------------------------------

class TestFirewallPolicies:
    def test_policy_count(self, ir):
        assert len(ir["firewall_policies"]) == 4

    def test_lan_to_wan_rule(self, ir):
        rule = next(r for r in ir["firewall_policies"] if r["name"] == "LAN-to-WAN")
        assert rule["action"] == "allow"
        assert rule["enabled"] is True
        assert rule["logging_enabled"] is True

    def test_allow_https_dmz(self, ir):
        rule = next(r for r in ir["firewall_policies"] if "HTTPS" in r["name"])
        assert rule["action"] == "allow"
        assert "HTTPS" in rule["services"]

    def test_deny_all_inbound(self, ir):
        rule = next(r for r in ir["firewall_policies"] if "Deny" in r["name"])
        assert rule["action"] == "drop"
        assert rule["logging_enabled"] is True

    def test_temp_any_any_no_log(self, ir):
        rule = next(r for r in ir["firewall_policies"] if "TEMP" in r["name"])
        assert rule["action"] == "allow"
        assert rule["logging_enabled"] is False
        assert "Any" in rule["source_addresses"] or "any" in [a.lower() for a in rule["source_addresses"]]

    def test_zones_populated(self, ir):
        rule = next(r for r in ir["firewall_policies"] if r["name"] == "LAN-to-WAN")
        assert "LAN" in rule["source_zones"]
        assert "WAN" in rule["destination_zones"]


# ---------------------------------------------------------------------------
# VPN
# ---------------------------------------------------------------------------

class TestVPN:
    def test_ipsec_tunnel_count(self, ir):
        assert len(ir["vpn"]["ipsec_tunnels"]) == 2

    def test_hq_ipsec_ikev2(self, ir):
        t = next(t for t in ir["vpn"]["ipsec_tunnels"] if "HQ" in t["name"])
        assert t["phase1"]["ike_version"] == 2
        assert "aes256" in t["phase1"]["encryption"]
        assert "sha256" in t["phase1"]["authentication"]
        assert 14 in t["phase1"]["dh_groups"]
        assert t["remote_gateway"] == "198.51.100.10"

    def test_hq_phase2(self, ir):
        t = next(t for t in ir["vpn"]["ipsec_tunnels"] if "HQ" in t["name"])
        assert "aes256" in t["phase2"]["encryption"]
        assert t["phase2"]["pfs_enabled"] is True

    def test_legacy_ipsec_ikev1_weak_crypto(self, ir):
        t = next(t for t in ir["vpn"]["ipsec_tunnels"] if "LEGACY" in t["name"])
        assert t["phase1"]["ike_version"] == 1
        assert "3des" in t["phase1"]["encryption"]
        assert "md5" in t["phase1"]["authentication"]

    def test_legacy_dh_group2(self, ir):
        t = next(t for t in ir["vpn"]["ipsec_tunnels"] if "LEGACY" in t["name"])
        assert 2 in t["phase1"]["dh_groups"]

    def test_legacy_pfs_disabled(self, ir):
        t = next(t for t in ir["vpn"]["ipsec_tunnels"] if "LEGACY" in t["name"])
        assert t["phase2"]["pfs_enabled"] is False

    def test_ssl_vpn_enabled(self, ir):
        assert ir["vpn"]["ssl_vpn"]["enabled"] is True

    def test_ssl_vpn_tls_min(self, ir):
        tls = ir["vpn"]["ssl_vpn"].get("tls_versions")
        assert tls is not None
        assert any("1.2" in v for v in tls)


# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------

class TestInterfaces:
    def test_interface_count(self, ir):
        assert len(ir["interfaces"]) == 2

    def test_lan_interface(self, ir):
        iface = next(i for i in ir["interfaces"] if i["name"] == "Port1")
        assert iface["zone"] == "LAN"
        assert iface["ip_address"] == "10.10.1.1"

    def test_wan_interface(self, ir):
        iface = next(i for i in ir["interfaces"] if i["name"] == "Port2")
        assert iface["zone"] == "WAN"


# ---------------------------------------------------------------------------
# Network objects
# ---------------------------------------------------------------------------

class TestNetworkObjects:
    def test_address_objects(self, ir):
        objs = ir["network_objects"]["address_objects"]
        names = {o["name"] for o in objs}
        assert "CORP-NET" in names
        assert "DMZ-SERVER" in names

    def test_corp_net_type(self, ir):
        obj = next(o for o in ir["network_objects"]["address_objects"] if o["name"] == "CORP-NET")
        assert obj["type"] == "network"

    def test_service_objects(self, ir):
        services = ir["network_objects"]["service_objects"]
        names = {s["name"] for s in services}
        assert "HTTPS" in names

    def test_https_service_port(self, ir):
        svc = next(s for s in ir["network_objects"]["service_objects"] if s["name"] == "HTTPS")
        assert svc["port_range"] == "443"
