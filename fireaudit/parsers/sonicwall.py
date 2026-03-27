"""SonicWall SonicOS XML configuration parser.

Parses the XML export from SonicWall SonicOS (``<SonicwallConfig>`` root)
into the FireAudit normalized IR.

Root structure::

  <SonicwallConfig FirmwareVer="SonicOS Enhanced 6.5.x">
    <General>         - hostname, serial number, model
    <ManagementSettings> / <SecurityServices>
                      - admin timeout, login policy, password policy, banner
    <Network><Interfaces>
                      - interface list
    <Users><LocalUser> - local user accounts
    <Syslog>          - syslog server(s)
    <NTP>             - NTP servers
    <SNMP>            - SNMP configuration
    <TrustedHosts>    - management source restrictions
    <RadiusSettings>  - RADIUS authentication
    <AccessRules><Rule>
                      - firewall policies
    <AddressObjects>  - address object definitions
    <VPNPolicies><Policy>
                      - IPsec VPN tunnels
    <SSLVPN>          - SSL-VPN settings
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from fireaudit.parsers.base import BaseParser, infer_interface_role


# ---------------------------------------------------------------------------
# ElementTree helpers
# ---------------------------------------------------------------------------

def _text(el: ET.Element | None, path: str, default: str | None = None) -> str | None:
    """Return stripped text of the first matching child, or *default*."""
    if el is None:
        return default
    node = el.find(path)
    return node.text.strip() if (node is not None and node.text) else default


def _bool_tag(el: ET.Element | None, path: str) -> bool:
    """Return True when the element exists and its text is not a falsy value."""
    if el is None:
        return False
    node = el.find(path)
    if node is None:
        return False
    text = (node.text or "").strip().lower()
    return text not in ("false", "0", "disabled", "no", "disable")


def _int(el: ET.Element | None, path: str) -> int | None:
    """Return integer value of a child element, or None."""
    val = _text(el, path)
    if val is None:
        return None
    try:
        return int(val)
    except ValueError:
        return None


def _normalize_encryption(raw: str) -> str:
    """Normalise encryption algorithm names to lowercase compact form.

    Examples:
        "AES-256"  -> "aes256"
        "3DES"     -> "3des"
        "AES128"   -> "aes128"
    """
    return raw.replace("-", "").lower()


def _normalize_tls(raw: str) -> str:
    """Normalise TLS version strings.

    "TLS 1.2"  -> "TLSv1.2"
    "TLS 1.3"  -> "TLSv1.3"
    Already in TLSv1.x format is returned unchanged.
    """
    s = raw.strip()
    if s.lower().startswith("tls "):
        return "TLSv" + s[4:]
    if s.lower().startswith("tlsv"):
        return s
    return s


def _parse_dh_group(raw: str | None) -> int | None:
    """Parse a DH group value such as "14", "DH14", "group14" -> 14."""
    if raw is None:
        return None
    stripped = raw.strip().lower().lstrip("dh").lstrip("group")
    try:
        return int(stripped)
    except ValueError:
        return None


def _parse_action(raw: str) -> str:
    """Map SonicWall action strings to the IR action vocabulary."""
    mapping = {
        "allow": "allow",
        "permit": "allow",
        "deny": "deny",
        "block": "deny",
        "drop": "deny",
    }
    return mapping.get(raw.strip().lower(), "deny")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class SonicWallParser(BaseParser):
    """Parser for SonicWall SonicOS XML configuration exports."""

    vendor = "sonicwall"

    SUPPORTED_ROOT = "SonicwallConfig"

    def parse(self, content: str) -> dict:
        try:
            root = ET.fromstring(content)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid XML: {exc}") from exc

        if root.tag != self.SUPPORTED_ROOT:
            raise ValueError(
                f"Unexpected root element <{root.tag}>. Expected <{self.SUPPORTED_ROOT}>"
            )

        ir = self._base_ir()
        ir["meta"]["vendor"] = self.vendor

        # Locate the management settings block — SonicOS uses different names
        # across firmware versions.
        mgmt = root.find("ManagementSettings")
        if mgmt is None:
            mgmt = root.find("SecurityServices")
        if mgmt is None:
            mgmt = root.find("Administration")

        general = root.find("General")
        network = root.find("Network")
        users_el = root.find("Users")
        syslog_el = root.find("Syslog")
        ntp_el = root.find("NTP")
        snmp_el = root.find("SNMP")
        trusted_el = root.find("TrustedHosts")
        radius_el = root.find("RadiusSettings")
        rules_el = root.find("AccessRules")
        addr_el = root.find("AddressObjects")
        vpn_el = root.find("VPNPolicies")
        sslvpn_el = root.find("SSLVPN")

        self._extract_meta(root, general, ir)
        self._extract_admin_access(mgmt, snmp_el, trusted_el, ir)
        self._extract_authentication(mgmt, users_el, radius_el, ir)
        self._extract_logging(syslog_el, ntp_el, ir)
        self._extract_vpn(vpn_el, sslvpn_el, ir)
        self._extract_firewall_policies(rules_el, ir)
        self._extract_interfaces(network, ir)
        self._extract_network_objects(addr_el, ir)

        return ir

    # ------------------------------------------------------------------
    # Section extractors
    # ------------------------------------------------------------------

    def _extract_meta(
        self,
        root: ET.Element,
        general: ET.Element | None,
        ir: dict,
    ) -> None:
        firmware = root.get("FirmwareVer")
        ir["meta"]["firmware_version"] = firmware.strip() if firmware else None
        ir["meta"]["hostname"] = _text(general, "SystemName")
        ir["meta"]["serial_number"] = _text(general, "SerialNumber")
        ir["meta"]["model"] = _text(general, "Model")

    def _extract_admin_access(
        self,
        mgmt: ET.Element | None,
        snmp_el: ET.Element | None,
        trusted_el: ET.Element | None,
        ir: dict,
    ) -> None:
        aa = ir["admin_access"]

        # --- Management protocols ---
        https_enabled = _bool_tag(mgmt, "HTTPSMgmt")
        http_enabled = _bool_tag(mgmt, "HTTPMgmt")
        ssh_enabled = _bool_tag(mgmt, "SSHMgmt")
        telnet_enabled = _bool_tag(mgmt, "TelnetMgmt")

        protocols: list[dict] = [
            {"protocol": "https", "enabled": https_enabled, "port": 443, "interfaces": [], "version": None},
            {"protocol": "http",  "enabled": http_enabled,  "port": 80,  "interfaces": [], "version": None},
            {"protocol": "ssh",   "enabled": ssh_enabled,   "port": 22,  "interfaces": [], "version": "2"},
            {"protocol": "telnet","enabled": telnet_enabled, "port": 23,  "interfaces": [], "version": None},
        ]
        aa["management_protocols"] = protocols

        aa["https_settings"]["enabled"] = https_enabled
        aa["ssh_settings"]["enabled"] = ssh_enabled
        aa["ssh_settings"]["version"] = 2
        # SSH cipher extraction — SonicOS may expose SSH cipher config under
        # <ManagementSettings> as <SSHCiphers> or <SSHEncryption>.  These elements
        # are not present in all firmware versions; leave as empty list if absent.
        ssh_ciphers_raw = _text(mgmt, "SSHCiphers") or _text(mgmt, "SSHEncryption")
        if ssh_ciphers_raw:
            # Value may be a comma- or space-separated list of cipher names.
            ciphers = [c.strip() for c in re.split(r"[,\s]+", ssh_ciphers_raw) if c.strip()]
            if ciphers:
                aa["ssh_settings"]["ciphers"] = ciphers

        # --- TLS minimum version for HTTPS management ---
        # SonicOS may use TLSMinVersion, MinTLSVersion, or SSLMinVersion
        tls_min_raw = (
            _text(mgmt, "TLSMinVersion")
            or _text(mgmt, "MinTLSVersion")
            or _text(mgmt, "SSLMinVersion")
        )
        if tls_min_raw:
            raw = tls_min_raw.strip()
            # Normalise variants: "TLS1.2", "TLS12", "TLSv1.2", "TLS 1.2" -> "TLSv1.2"
            raw_lower = raw.lower().replace(" ", "").replace("_", "")
            if raw_lower in ("tls1.2", "tls12", "tlsv1.2"):
                tls_ver = "TLSv1.2"
            elif raw_lower in ("tls1.3", "tls13", "tlsv1.3"):
                tls_ver = "TLSv1.3"
            elif raw_lower in ("tls1.1", "tls11", "tlsv1.1"):
                tls_ver = "TLSv1.1"
            elif raw_lower in ("tls1.0", "tls10", "tlsv1.0", "tls1"):
                tls_ver = "TLSv1.0"
            else:
                tls_ver = _normalize_tls(raw)
            aa["https_settings"]["tls_versions"] = [tls_ver]

        # --- Session timeout (minutes -> seconds) ---
        timeout_min = _int(mgmt, "AdminIdleTimeout")
        aa["session_timeout_seconds"] = timeout_min * 60 if timeout_min is not None else None

        # --- Login policy ---
        aa["max_login_attempts"] = _int(mgmt, "MaxLoginAttempts")
        aa["lockout_duration_seconds"] = _int(mgmt, "LockoutPeriod")

        # --- Banner ---
        banner_text = _text(mgmt, "LoginBanner")
        banner_enabled = _bool_tag(mgmt, "BannerEnabled")
        aa["banner"] = banner_text
        aa["banner_enabled"] = banner_enabled

        # --- Trusted hosts ---
        hosts: list[str] = []
        if trusted_el is not None:
            for host_el in trusted_el.findall("Host"):
                val = (host_el.text or "").strip()
                if val:
                    hosts.append(val)
        aa["trusted_hosts"] = hosts

        # --- SNMP ---
        snmp = aa["snmp"]
        if snmp_el is not None:
            snmp["enabled"] = _bool_tag(snmp_el, "Enabled")
            raw_ver = _text(snmp_el, "Version") or ""
            # Normalise "SNMPv3" -> "SNMPv3", "v2c" -> "SNMPv2c", etc.
            snmp["version"] = raw_ver if raw_ver else None
            community = _text(snmp_el, "CommunityString")
            if community:
                snmp["community_strings"] = [community]
            # SNMPv3 security level (SonicWall uses SecurityLevel element)
            sec_level_raw = (_text(snmp_el, "SecurityLevel") or "").lower()
            if "authpriv" in sec_level_raw or "auth-priv" in sec_level_raw or sec_level_raw == "3":
                snmp["security_level"] = "auth-priv"
            elif "authnopriv" in sec_level_raw or "auth-no-priv" in sec_level_raw or sec_level_raw == "2":
                snmp["security_level"] = "auth-no-priv"
            elif sec_level_raw in ("noauth", "noauthnopriv", "1"):
                snmp["security_level"] = "no-auth-no-priv"

    def _extract_authentication(
        self,
        mgmt: ET.Element | None,
        users_el: ET.Element | None,
        radius_el: ET.Element | None,
        ir: dict,
    ) -> None:
        auth = ir["authentication"]

        # --- Password policy ---
        pp = auth["password_policy"]
        pp["min_length"] = _int(mgmt, "MinPasswordLength")
        pp["max_age_days"] = _int(mgmt, "PasswordMaxAge")
        if mgmt is not None:
            complexity = _bool_tag(mgmt, "PasswordComplexity")
            # SonicWall PasswordComplexity flag implies all character classes
            pp["require_uppercase"] = complexity
            pp["require_lowercase"] = complexity
            pp["require_numbers"] = complexity
            pp["require_special"] = complexity
        pp["lockout_threshold"] = _int(mgmt, "MaxLoginAttempts")
        # Password history count — SonicOS may use PasswordHistory or PwdHistory
        history = _int(mgmt, "PasswordHistory") or _int(mgmt, "PwdHistory")
        if history is not None:
            pp["history_count"] = history

        # --- Local users ---
        users: list[dict] = []
        default_admin_exists = False

        if users_el is not None:
            for user_el in users_el.findall("LocalUser"):
                username = _text(user_el, "Name") or ""
                if not username:
                    continue
                if username.lower() == "admin":
                    default_admin_exists = True

                enabled = _bool_tag(user_el, "Enabled")
                admin_rights = _bool_tag(user_el, "AdminRights")
                mfa = _bool_tag(user_el, "TwoFactorEnabled")

                users.append({
                    "username": username,
                    "privilege_level": "superuser" if admin_rights else "user",
                    "mfa_enabled": mfa,
                    "password_hash_algorithm": None,
                    "account_enabled": enabled,
                })

        auth["local_users"] = users
        auth["default_admin_account_exists"] = default_admin_exists
        auth["default_admin_renamed"] = not default_admin_exists

        # --- RADIUS ---
        ra = auth["remote_auth"]
        servers: list[dict] = []
        if radius_el is not None and _bool_tag(radius_el, "Enabled"):
            ra["radius_enabled"] = True
            host = _text(radius_el, "Server")
            port = _int(radius_el, "Port") or 1812
            if host:
                servers.append({"type": "radius", "host": host, "port": port})
        ra["servers"] = servers

    def _extract_logging(
        self,
        syslog_el: ET.Element | None,
        ntp_el: ET.Element | None,
        ir: dict,
    ) -> None:
        log = ir["logging"]

        # --- Syslog ---
        syslog_servers: list[dict] = []
        if syslog_el is not None and _bool_tag(syslog_el, "Enabled"):
            for srv in syslog_el.findall("Server"):
                host = _text(srv, "IPAddress")
                if not host:
                    continue
                port = _int(srv, "Port") or 514
                proto_raw = (_text(srv, "Protocol") or "udp").lower()
                # Normalise to IR vocabulary: udp | tcp | tls
                proto_map = {"udp": "udp", "tcp": "tcp", "tls": "tls", "ssl": "tls"}
                proto = proto_map.get(proto_raw, "udp")
                syslog_servers.append({
                    "host": host,
                    "port": port,
                    "protocol": proto,
                    "facility": None,
                    "severity": None,
                })
        log["syslog_servers"] = syslog_servers

        # --- NTP ---
        ntp_servers: list[str] = []
        ntp_enabled = False
        if ntp_el is not None:
            ntp_enabled = _bool_tag(ntp_el, "Enabled")
            for key in ("Server1", "Server2", "Server3"):
                val = _text(ntp_el, key)
                if val:
                    ntp_servers.append(val)
        log["ntp_servers"] = ntp_servers
        log["ntp_enabled"] = ntp_enabled if ntp_el is not None else None

    def _extract_vpn(
        self,
        vpn_el: ET.Element | None,
        sslvpn_el: ET.Element | None,
        ir: dict,
    ) -> None:
        vpn = ir["vpn"]

        # --- IPsec tunnels ---
        tunnels: list[dict] = []
        if vpn_el is not None:
            for idx, policy in enumerate(vpn_el.findall("Policy"), start=1):
                name = _text(policy, "Name") or f"tunnel-{idx}"
                enabled = _bool_tag(policy, "Enabled")
                gateway = _text(policy, "GatewayIP")

                auth_raw = (_text(policy, "AuthMethod") or "PSK").upper()
                auth_map = {"PSK": "psk", "CERTIFICATE": "certificate", "CERT": "certificate", "EAP": "eap"}
                auth_method = auth_map.get(auth_raw, "psk")

                ike_raw = _text(policy, "IKEVersion") or "IKEv1"
                ike_version = 2 if "2" in ike_raw else 1

                p1_enc_raw = _text(policy, "Phase1Encryption") or ""
                p1_auth_raw = _text(policy, "Phase1Auth") or ""
                p1_dh_raw = _text(policy, "Phase1DHGroup")

                p2_enc_raw = _text(policy, "Phase2Encryption") or ""
                p2_auth_raw = _text(policy, "Phase2Auth") or ""
                p2_dh_raw = _text(policy, "Phase2DHGroup")

                pfs_enabled = _bool_tag(policy, "PFS")

                p1_dh = _parse_dh_group(p1_dh_raw)
                p2_dh = _parse_dh_group(p2_dh_raw)

                mode_raw = (_text(policy, "Mode") or _text(policy, "Phase1Mode") or "main").lower()
                aggressive_mode = "aggressive" in mode_raw and ike_version == 1

                tunnels.append({
                    "name": name,
                    "enabled": enabled,
                    "remote_gateway": gateway,
                    "phase1": {
                        "encryption": [_normalize_encryption(p1_enc_raw)] if p1_enc_raw else [],
                        "authentication": [p1_auth_raw.lower()] if p1_auth_raw else [],
                        "dh_groups": [p1_dh] if p1_dh is not None else [],
                        "lifetime_seconds": 28800,
                        "pfs_enabled": pfs_enabled,
                        "ike_version": ike_version,
                        "aggressive_mode": aggressive_mode,
                    },
                    "phase2": {
                        "encryption": [_normalize_encryption(p2_enc_raw)] if p2_enc_raw else [],
                        "authentication": [p2_auth_raw.lower()] if p2_auth_raw else [],
                        "dh_groups": [p2_dh] if p2_dh is not None else [],
                        "lifetime_seconds": 3600,
                        "pfs_enabled": pfs_enabled,
                    },
                    "auth_method": auth_method,
                })

        vpn["ipsec_tunnels"] = tunnels

        # --- SSL VPN ---
        ssl_vpn = vpn["ssl_vpn"]
        if sslvpn_el is not None:
            ssl_vpn["enabled"] = _bool_tag(sslvpn_el, "Enabled")
            tls_min_raw = _text(sslvpn_el, "TLSMinVersion")
            if tls_min_raw:
                ssl_vpn["tls_versions"] = [_normalize_tls(tls_min_raw)]
            ssl_vpn["client_certificate_required"] = _bool_tag(sslvpn_el, "ClientCertRequired")
            ssl_vpn["split_tunneling"] = _bool_tag(sslvpn_el, "SplitTunneling")

    def _extract_firewall_policies(
        self,
        rules_el: ET.Element | None,
        ir: dict,
    ) -> None:
        policies: list[dict] = []
        if rules_el is None:
            ir["firewall_policies"] = policies
            return

        for idx, rule in enumerate(rules_el.findall("Rule"), start=1):
            name = _text(rule, "Name") or f"rule-{idx}"
            enabled = _bool_tag(rule, "Enabled")
            action_raw = _text(rule, "Action") or "Deny"
            action = _parse_action(action_raw)

            from_zone = _text(rule, "FromZone") or ""
            to_zone = _text(rule, "ToZone") or ""

            src_raw = _text(rule, "Source") or "Any"
            dst_raw = _text(rule, "Destination") or "Any"
            svc_raw = _text(rule, "Service") or "Any"

            # Normalise "Any" to the IR convention "any"
            src_addrs = ["any"] if src_raw.lower() == "any" else [src_raw]
            dst_addrs = ["any"] if dst_raw.lower() == "any" else [dst_raw]
            services = ["any"] if svc_raw.lower() == "any" else [svc_raw]

            logging_enabled = _bool_tag(rule, "Log")
            comment = _text(rule, "Comment")

            policies.append({
                "id": idx,
                "name": name,
                "enabled": enabled,
                "action": action,
                "source_zones": [from_zone] if from_zone else [],
                "destination_zones": [to_zone] if to_zone else [],
                "source_addresses": src_addrs,
                "destination_addresses": dst_addrs,
                "services": services,
                "protocols": [],
                "source_ports": [],
                "destination_ports": [],
                "logging_enabled": logging_enabled,
                "comment": comment,
                "schedule": None,
                "nat_enabled": False,
            })

        ir["firewall_policies"] = policies

    def _extract_interfaces(
        self,
        network: ET.Element | None,
        ir: dict,
    ) -> None:
        iface_list: list[dict] = []
        if network is None:
            ir["interfaces"] = iface_list
            return

        interfaces_el = network.find("Interfaces")
        if interfaces_el is None:
            ir["interfaces"] = iface_list
            return

        for iface_el in interfaces_el.findall("Interface"):
            name = _text(iface_el, "Name") or ""
            if not name:
                continue

            zone = _text(iface_el, "Zone") or ""
            ip_addr = _text(iface_el, "IPAddress")
            netmask = _text(iface_el, "SubnetMask")
            enabled = _bool_tag(iface_el, "Enabled")
            comment = _text(iface_el, "Comment")

            mgmt_access: list[str] = []
            if _bool_tag(iface_el, "MgmtHTTPS"):
                mgmt_access.append("https")
            if _bool_tag(iface_el, "MgmtSSH"):
                mgmt_access.append("ssh")
            if _bool_tag(iface_el, "MgmtPing"):
                mgmt_access.append("ping")

            iface_list.append({
                "name": name,
                "type": "physical",
                "role": infer_interface_role(zone, name),
                "zone": zone,
                "ip_address": ip_addr,
                "netmask": netmask,
                "enabled": enabled,
                "management_access": mgmt_access,
                "description": comment,
            })

        ir["interfaces"] = iface_list

    def _extract_network_objects(
        self,
        addr_el: ET.Element | None,
        ir: dict,
    ) -> None:
        address_objects: list[dict] = []
        if addr_el is not None:
            for obj in addr_el.findall("AddressObject"):
                name = _text(obj, "Name") or ""
                if not name:
                    continue
                type_raw = (_text(obj, "Type") or "host").lower()
                # Normalise to IR vocabulary: host | network | range | fqdn | group | any
                type_map = {
                    "host": "host",
                    "network": "network",
                    "range": "range",
                    "fqdn": "fqdn",
                    "group": "group",
                }
                obj_type = type_map.get(type_raw, "host")

                ip = _text(obj, "IPAddress")
                mask = _text(obj, "SubnetMask")
                if obj_type == "network" and ip and mask:
                    value = f"{ip}/{mask}"
                elif ip:
                    value = ip
                else:
                    value = None

                address_objects.append({
                    "name": name,
                    "type": obj_type,
                    "value": value,
                })

        ir["network_objects"]["address_objects"] = address_objects
