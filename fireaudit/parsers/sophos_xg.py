"""Sophos XG / SFOS XML configuration parser.

Parses the XML backup exported from Sophos XG / SFOS devices into the
FireAudit IR.

Sophos XG XML backup root structure::

  <Configuration firmware_version="SFOS 18.5.3 MR-3">
    <Global>
      <SystemInformation>…</SystemInformation>
      <AdminSettings>…</AdminSettings>
      <ManagementProtocols>…</ManagementProtocols>
      <TLSSettings>…</TLSSettings>
      <TrustedHosts>…</TrustedHosts>
      <SNMPSettings>…</SNMPSettings>
    </Global>
    <NTP>…</NTP>
    <Syslog>…</Syslog>
    <Network>…</Network>
    <Firewall>…</Firewall>
    <Hosts>…</Hosts>
    <Services>…</Services>
    <Authentication>…</Authentication>
    <VPN>…</VPN>
  </Configuration>
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from fireaudit.parsers.base import BaseParser, infer_interface_role


# ---------------------------------------------------------------------------
# ElementTree helpers
# ---------------------------------------------------------------------------

def _text(el: ET.Element | None, path: str, default: str | None = None) -> str | None:
    """Find element by path and return its stripped text, or *default*."""
    if el is None:
        return default
    node = el.find(path)
    return node.text.strip() if (node is not None and node.text) else default


def _int(el: ET.Element | None, path: str) -> int | None:
    """Find element by path and return its integer value, or None."""
    val = _text(el, path)
    if val is None:
        return None
    try:
        return int(val)
    except ValueError:
        return None


def _enabled(el: ET.Element | None, path: str) -> bool | None:
    """Return True if element text is 'Enable', False if 'Disable', None if absent."""
    val = _text(el, path)
    if val is None:
        return None
    return val.strip().lower() == "enable"


def _all_text(el: ET.Element | None, child_tag: str) -> list[str]:
    """Return text from every direct child with *child_tag* under *el*."""
    if el is None:
        return []
    return [c.text.strip() for c in el.findall(child_tag) if c.text]


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _norm_encryption(raw: str) -> str:
    """Normalise Sophos XG encryption algorithm names to lowercase IR tokens."""
    mapping: dict[str, str] = {
        "AES256": "aes256",
        "AES192": "aes192",
        "AES128": "aes128",
        "3DES":   "3des",
        "DES":    "des",
        "NULL":   "null",
    }
    return mapping.get(raw, raw.lower())


def _norm_hash(raw: str) -> str:
    """Normalise Sophos XG hash / authentication algorithm names."""
    mapping: dict[str, str] = {
        "SHA2_256":  "sha256",
        "SHA2_384":  "sha384",
        "SHA2_512":  "sha512",
        "SHA1":      "sha1",
        "MD5":       "md5",
        "SHA2-256":  "sha256",
        "SHA2-384":  "sha384",
        "SHA2-512":  "sha512",
        "SHA-1":     "sha1",
    }
    return mapping.get(raw, raw.lower())


def _action(raw: str) -> str:
    """Map Sophos XG firewall rule actions to IR action tokens."""
    mapping: dict[str, str] = {
        "accept": "allow",
        "drop":   "drop",
        "reject": "deny",
    }
    return mapping.get(raw.lower(), raw.lower())


def _parse_tls_min(raw: str) -> list[str]:
    """Convert a minimum TLS version string into the list of supported versions."""
    r = raw.lower()
    if "1.3" in r:
        return ["TLSv1.3"]
    if "1.2" in r:
        return ["TLSv1.2", "TLSv1.3"]
    if "1.1" in r:
        return ["TLSv1.1", "TLSv1.2", "TLSv1.3"]
    if "1.0" in r:
        return ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    return ["TLSv1.2", "TLSv1.3"]


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

class SophosXGParser(BaseParser):
    """Parser for Sophos XG / SFOS XML backup configuration files."""

    vendor = "sophos_xg"

    def parse(self, content: str) -> dict:
        try:
            root = ET.fromstring(content)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid XML: {exc}") from exc

        # Accept both <Configuration> (SFOS export) and <config> (alternative)
        if root.tag in ("Configuration", "config"):
            cfg = root
        else:
            cfg = root.find(".//Configuration") or root.find(".//config") or root

        ir = self._base_ir()

        self._extract_meta(cfg, ir)
        self._extract_admin_access(cfg, ir)
        self._extract_authentication(cfg, ir)
        self._extract_logging(cfg, ir)
        self._extract_vpn(cfg, ir)
        self._extract_firewall_policies(cfg, ir)
        self._extract_interfaces(cfg, ir)
        self._extract_network_objects(cfg, ir)

        return ir

    # ------------------------------------------------------------------
    # Section extractors
    # ------------------------------------------------------------------

    def _extract_meta(self, cfg: ET.Element, ir: dict) -> None:
        meta = ir["meta"]

        # firmware_version is a root attribute on <Configuration>
        meta["firmware_version"] = cfg.get("firmware_version") or cfg.get("version")

        sys_info = cfg.find("Global/SystemInformation")
        meta["hostname"] = _text(sys_info, "SystemName")
        meta["model"] = _text(sys_info, "Model")

    def _extract_admin_access(self, cfg: ET.Element, ir: dict) -> None:
        aa = ir["admin_access"]
        admin_el = cfg.find("Global/AdminSettings")
        mgmt_el = cfg.find("Global/ManagementProtocols")
        tls_el = cfg.find("Global/TLSSettings")
        trusted_el = cfg.find("Global/TrustedHosts")
        snmp_el = cfg.find("Global/SNMPSettings")

        # --- Management protocols ---
        https_en = _enabled(mgmt_el, "HTTPS")
        if https_en is None:
            https_en = True  # default on XG
        http_en = _enabled(mgmt_el, "HTTP")
        if http_en is None:
            http_en = False
        ssh_en = _enabled(mgmt_el, "SSH")
        if ssh_en is None:
            ssh_en = True
        telnet_en = _enabled(mgmt_el, "Telnet")
        if telnet_en is None:
            telnet_en = False

        https_port = _int(admin_el, "HTTPSPort") or 4444
        ssh_port = _int(admin_el, "SSHPort") or 22

        protocols: list[dict] = [
            {
                "protocol": "https",
                "enabled": https_en,
                "port": https_port,
                "interfaces": [],
                "version": None,
            },
            {
                "protocol": "http",
                "enabled": http_en,
                "port": 80,
                "interfaces": [],
                "version": None,
            },
            {
                "protocol": "ssh",
                "enabled": ssh_en,
                "port": ssh_port,
                "interfaces": [],
                "version": "2",
            },
            {
                "protocol": "telnet",
                "enabled": telnet_en,
                "port": 23,
                "interfaces": [],
                "version": None,
            },
        ]
        aa["management_protocols"] = protocols

        # --- HTTPS / TLS settings ---
        aa["https_settings"]["enabled"] = https_en
        tls_min_raw = _text(tls_el, "MinTLSVersion")
        if tls_min_raw:
            aa["https_settings"]["tls_versions"] = _parse_tls_min(tls_min_raw)

        # --- SSH ---
        aa["ssh_settings"]["enabled"] = ssh_en
        aa["ssh_settings"]["version"] = 2

        # --- Session / lockout ---
        idle = _int(admin_el, "IdleSessionTimeout")
        aa["session_timeout_seconds"] = idle * 60 if idle is not None else None
        aa["max_login_attempts"] = _int(admin_el, "MaximumLoginAttempts")
        lockout = _int(admin_el, "LockoutDuration")
        aa["lockout_duration_seconds"] = lockout  # already in seconds on XG

        # --- Trusted hosts ---
        trusted: list[str] = _all_text(trusted_el, "Host")
        aa["trusted_hosts"] = trusted

        # --- Login banner ---
        banner = _text(admin_el, "LoginBanner")
        aa["banner"] = banner
        aa["banner_enabled"] = bool(banner)

        # --- SNMP ---
        if snmp_el is not None:
            snmp_enabled_val = _enabled(snmp_el, "Enabled")
            snmp_enabled = bool(snmp_enabled_val)
            aa["snmp"]["enabled"] = snmp_enabled
            version_raw = _text(snmp_el, "Version")
            if version_raw:
                aa["snmp"]["version"] = version_raw.lower() if version_raw.lower().startswith("v") else f"v{version_raw}"
            community = _text(snmp_el, "CommunityName")
            if community:
                aa["snmp"]["community_strings"] = [community]
            # SNMPv3 security level
            sec_raw = (_text(snmp_el, "SecurityLevel") or _text(snmp_el, "V3SecurityLevel") or "").lower()
            if "authpriv" in sec_raw or "auth_priv" in sec_raw or "auth-priv" in sec_raw:
                aa["snmp"]["security_level"] = "auth-priv"
            elif "authnopriv" in sec_raw or "auth-no-priv" in sec_raw or "auth_no_priv" in sec_raw:
                aa["snmp"]["security_level"] = "auth-no-priv"
            elif sec_raw in ("noauth", "noauthnopriv", "no-auth-no-priv"):
                aa["snmp"]["security_level"] = "no-auth-no-priv"

    def _extract_authentication(self, cfg: ET.Element, ir: dict) -> None:
        auth = ir["authentication"]
        auth_el = cfg.find("Authentication")

        # --- Password policy ---
        # Source 1: Global/AdminSettings (device-level)
        admin_el = cfg.find("Global/AdminSettings")
        # Source 2: Authentication/PasswordPolicy (may override or supplement)
        pw_el = cfg.find("Authentication/PasswordPolicy")

        pp = auth["password_policy"]
        min_len = _int(pw_el, "MinLength") or _int(admin_el, "PasswordMinLength")
        pp["min_length"] = min_len

        complexity_raw = _text(pw_el, "Complexity") or _text(admin_el, "PasswordComplexity")
        complexity_enabled = (complexity_raw or "").strip().lower() == "enable"
        if complexity_enabled:
            pp["require_uppercase"] = True
            pp["require_lowercase"] = True
            pp["require_numbers"] = True
            pp["require_special"] = True

        max_age = _int(pw_el, "MaxAge") or _int(admin_el, "PasswordMaxAge")
        pp["max_age_days"] = max_age
        history = _int(pw_el, "History") or _int(admin_el, "PasswordHistory")
        pp["history_count"] = history
        pp["lockout_threshold"] = _int(admin_el, "MaximumLoginAttempts")

        # --- Local users ---
        users: list[dict] = []
        default_admin_exists = False
        if auth_el is not None:
            for user_el in auth_el.findall("LocalUser"):
                username = _text(user_el, "Username") or ""
                if username.lower() == "admin":
                    default_admin_exists = True
                user_type = _text(user_el, "UserType") or "User"
                role = "administrator" if user_type.lower() == "administrator" else "user"
                account_enabled = _enabled(user_el, "Status")
                if account_enabled is None:
                    account_enabled = True
                mfa_enabled = _enabled(user_el, "MFA")
                users.append({
                    "username": username,
                    "privilege_level": role,
                    "mfa_enabled": mfa_enabled if mfa_enabled is not None else False,
                    "password_hash_algorithm": None,
                    "account_enabled": account_enabled,
                })

        auth["local_users"] = users
        auth["default_admin_account_exists"] = default_admin_exists
        auth["default_admin_renamed"] = not default_admin_exists

        # --- Remote auth servers ---
        ra = auth["remote_auth"]
        servers: list[dict] = []

        if auth_el is not None:
            # RADIUS
            for radius_el in auth_el.findall("RADIUSServer"):
                enabled_val = _enabled(radius_el, "Enabled")
                if enabled_val is False:
                    continue
                host = _text(radius_el, "ServerAddress")
                port = _int(radius_el, "AuthPort") or 1812
                if host:
                    servers.append({"type": "radius", "host": host, "port": port})
            # TACACS+
            for tac_el in auth_el.findall("TACACSServer"):
                enabled_val = _enabled(tac_el, "Enabled")
                if enabled_val is False:
                    continue
                host = _text(tac_el, "ServerAddress")
                port = _int(tac_el, "Port") or 49
                if host:
                    servers.append({"type": "tacacs+", "host": host, "port": port})
            # LDAP
            for ldap_el in auth_el.findall("LDAPServer"):
                enabled_val = _enabled(ldap_el, "Enabled")
                if enabled_val is False:
                    continue
                host = _text(ldap_el, "ServerAddress")
                port = _int(ldap_el, "Port") or 389
                if host:
                    servers.append({"type": "ldap", "host": host, "port": port})

        ra["servers"] = servers
        ra["radius_enabled"] = any(s["type"] == "radius" for s in servers)
        ra["tacacs_enabled"] = any(s["type"] == "tacacs+" for s in servers)
        ra["ldap_enabled"] = any(s["type"] in ("ldap", "ldaps") for s in servers)

    def _extract_logging(self, cfg: ET.Element, ir: dict) -> None:
        log = ir["logging"]

        # --- Syslog servers ---
        syslog_servers: list[dict] = []
        syslog_el = cfg.find("Syslog")
        if syslog_el is not None:
            for srv_el in syslog_el.findall("SyslogServer"):
                enabled_val = _enabled(srv_el, "Enabled")
                # Include server regardless of enabled flag — IR captures config presence
                host = _text(srv_el, "IPAddress") or _text(srv_el, "Hostname") or ""
                if not host:
                    continue
                proto_raw = (_text(srv_el, "Protocol") or "UDP").upper()
                proto = proto_raw.lower()
                syslog_servers.append({
                    "host": host,
                    "port": _int(srv_el, "Port") or 514,
                    "protocol": proto,
                    "facility": _text(srv_el, "Facility"),
                    "severity": _text(srv_el, "Severity"),
                })

        log["syslog_servers"] = syslog_servers
        log["local_logging_enabled"] = True

        # --- NTP ---
        ntp_el = cfg.find("NTP")
        ntp_enabled_val = _enabled(ntp_el, "Enabled")
        ntp_servers: list[str] = _all_text(ntp_el, "Server")
        log["ntp_servers"] = ntp_servers
        log["ntp_enabled"] = bool(ntp_enabled_val) if ntp_enabled_val is not None else len(ntp_servers) > 0

    def _extract_vpn(self, cfg: ET.Element, ir: dict) -> None:
        vpn = ir["vpn"]
        vpn_el = cfg.find("VPN")

        # --- IPsec tunnels ---
        tunnels: list[dict] = []
        if vpn_el is not None:
            for conn_el in vpn_el.findall("IPSecConnection"):
                name = _text(conn_el, "Name") or ""
                enabled_val = _enabled(conn_el, "Status")
                enabled = enabled_val if enabled_val is not None else True

                remote_host = _text(conn_el, "RemoteHost")
                auth_mode_raw = (_text(conn_el, "AuthMode") or "PSK").lower()
                auth_method = "psk" if "psk" in auth_mode_raw else "certificate"

                ike_ver_raw = _text(conn_el, "IKEVersion") or "2"
                try:
                    ike_version: int | None = int(ike_ver_raw)
                except ValueError:
                    ike_version = 2

                # Phase 1
                p1_el = conn_el.find("Phase1Settings")
                p1_enc_raw = _text(p1_el, "Encryption") or ""
                p1_hash_raw = _text(p1_el, "Authentication") or ""
                p1_dh_raw = _text(p1_el, "DHGroup")
                p1_life = _int(p1_el, "Lifetime")
                p1_dh: list[int] = []
                if p1_dh_raw:
                    try:
                        p1_dh = [int(p1_dh_raw)]
                    except ValueError:
                        pass
                mode_raw = (_text(conn_el, "Mode") or _text(conn_el, "IKEMode") or "main").lower()
                aggressive_mode = "aggressive" in mode_raw and ike_version == 1
                phase1: dict[str, Any] = {
                    "encryption": [_norm_encryption(p1_enc_raw)] if p1_enc_raw else [],
                    "authentication": [_norm_hash(p1_hash_raw)] if p1_hash_raw else [],
                    "dh_groups": p1_dh,
                    "lifetime_seconds": p1_life,
                    "pfs_enabled": True,
                    "ike_version": ike_version,
                    "aggressive_mode": aggressive_mode,
                }

                # Phase 2
                p2_el = conn_el.find("Phase2Settings")
                p2_enc_raw = _text(p2_el, "Encryption") or ""
                p2_hash_raw = _text(p2_el, "Authentication") or ""
                p2_dh_raw = _text(p2_el, "DHGroup")
                p2_life = _int(p2_el, "Lifetime")
                pfs_enabled_val = _enabled(p2_el, "PFS")
                p2_dh: list[int] = []
                if p2_dh_raw:
                    try:
                        p2_dh = [int(p2_dh_raw)]
                    except ValueError:
                        pass
                phase2: dict[str, Any] = {
                    "encryption": [_norm_encryption(p2_enc_raw)] if p2_enc_raw else [],
                    "authentication": [_norm_hash(p2_hash_raw)] if p2_hash_raw else [],
                    "dh_groups": p2_dh,
                    "lifetime_seconds": p2_life,
                    "pfs_enabled": pfs_enabled_val if pfs_enabled_val is not None else True,
                }

                tunnels.append({
                    "name": name,
                    "enabled": enabled,
                    "remote_gateway": remote_host,
                    "phase1": phase1,
                    "phase2": phase2,
                    "auth_method": auth_method,
                })

        vpn["ipsec_tunnels"] = tunnels

        # --- SSL VPN ---
        ssl_vpn = vpn["ssl_vpn"]
        ssl_el = vpn_el.find("SSLVPNServerSettings") if vpn_el is not None else None
        if ssl_el is not None:
            ssl_enabled_val = _enabled(ssl_el, "Enabled")
            ssl_vpn["enabled"] = bool(ssl_enabled_val)
            tls_min_raw = _text(ssl_el, "TLSMinVersion")
            if tls_min_raw:
                ssl_vpn["tls_versions"] = _parse_tls_min(tls_min_raw)
            cert_required = _enabled(ssl_el, "ClientCertRequired")
            ssl_vpn["client_certificate_required"] = cert_required if cert_required is not None else False
            split_raw = _enabled(ssl_el, "SplitTunneling")
            ssl_vpn["split_tunneling"] = split_raw if split_raw is not None else None

    def _extract_firewall_policies(self, cfg: ET.Element, ir: dict) -> None:
        policies: list[dict] = []
        fw_el = cfg.find("Firewall")
        if fw_el is None:
            ir["firewall_policies"] = policies
            return

        rule_idx = 0
        for rule_el in fw_el.findall("FirewallRule"):
            rule_idx += 1
            name = _text(rule_el, "Name") or f"rule-{rule_idx}"
            enabled_val = _enabled(rule_el, "Status")
            enabled = enabled_val if enabled_val is not None else True

            action_raw = _text(rule_el, "Action") or "Drop"
            action = _action(action_raw)

            # Source / destination zones
            src_zones = _all_text(rule_el.find("SourceZones"), "Zone")
            dst_zones = _all_text(rule_el.find("DestZones"), "Zone")

            # Source / destination networks (address object names)
            src_addrs = _all_text(rule_el.find("SourceNetworks"), "Network")
            dst_addrs = _all_text(rule_el.find("DestNetworks"), "Network")

            # Services
            services = _all_text(rule_el.find("Services"), "Service")

            # Logging
            log_enabled = _enabled(rule_el, "LogTraffic")
            if log_enabled is None:
                log_enabled = False

            policies.append({
                "id": rule_idx,
                "name": name,
                "enabled": enabled,
                "action": action,
                "source_zones": src_zones,
                "destination_zones": dst_zones,
                "source_addresses": src_addrs,
                "destination_addresses": dst_addrs,
                "services": services,
                "protocols": [],
                "source_ports": [],
                "destination_ports": [],
                "logging_enabled": log_enabled,
                "comment": _text(rule_el, "Description"),
                "schedule": _text(rule_el, "Schedule"),
                "nat_enabled": False,
            })

        ir["firewall_policies"] = policies

    def _extract_interfaces(self, cfg: ET.Element, ir: dict) -> None:
        interfaces: list[dict] = []
        net_el = cfg.find("Network")
        if net_el is None:
            ir["interfaces"] = interfaces
            return

        for iface_el in net_el.findall("Interface"):
            name = _text(iface_el, "Name") or ""
            zone = _text(iface_el, "Zone")
            ip_addr = _text(iface_el, "IPAddress")
            netmask = _text(iface_el, "Netmask")
            enabled_val = _enabled(iface_el, "Status")
            enabled = enabled_val if enabled_val is not None else True
            description = _text(iface_el, "Description")

            interfaces.append({
                "name": name,
                "type": "ethernet",
                "role": infer_interface_role(zone, name),
                "zone": zone,
                "ip_address": ip_addr,
                "netmask": netmask,
                "enabled": enabled,
                "management_access": [],
                "description": description,
            })

        ir["interfaces"] = interfaces

    def _extract_network_objects(self, cfg: ET.Element, ir: dict) -> None:
        address_objects: list[dict] = []
        service_objects: list[dict] = []

        # Address / Host objects
        hosts_el = cfg.find("Hosts")
        if hosts_el is not None:
            for host_el in hosts_el.findall("Host"):
                name = _text(host_el, "Name") or ""
                host_type_raw = (_text(host_el, "HostType") or "IP").lower()
                if host_type_raw in ("network", "subnet"):
                    obj_type = "network"
                    ip = _text(host_el, "IPAddress")
                    subnet = _text(host_el, "Subnet") or _text(host_el, "Netmask")
                    value = f"{ip}/{subnet}" if ip and subnet else ip
                elif host_type_raw in ("range",):
                    obj_type = "range"
                    value = _text(host_el, "StartIPAddress")
                    end_ip = _text(host_el, "EndIPAddress")
                    if value and end_ip:
                        value = f"{value}-{end_ip}"
                elif host_type_raw in ("fqdn",):
                    obj_type = "fqdn"
                    value = _text(host_el, "FQDN")
                else:
                    # IP host or default
                    obj_type = "host"
                    value = _text(host_el, "IPAddress")

                address_objects.append({"name": name, "type": obj_type, "value": value})

        # Service objects
        services_el = cfg.find("Services")
        if services_el is not None:
            for svc_el in services_el.findall("Service"):
                name = _text(svc_el, "Name") or ""
                proto_raw = (_text(svc_el, "Protocol") or "").lower()
                if not proto_raw:
                    svc_type = (_text(svc_el, "Type") or "").lower()
                    if "tcp" in svc_type:
                        proto_raw = "tcp"
                    elif "udp" in svc_type:
                        proto_raw = "udp"
                    else:
                        proto_raw = svc_type
                port = _text(svc_el, "DestinationPort") or _text(svc_el, "Port")
                service_objects.append({"name": name, "protocol": proto_raw, "port_range": port})

        ir["network_objects"]["address_objects"] = address_objects
        ir["network_objects"]["service_objects"] = service_objects
