"""pfSense / OPNsense XML configuration parser.

Parses config.xml exported from pfSense or OPNsense into the FireAudit IR.

Root structure:
  <pfsense>          (pfSense uses this; OPNsense uses <opnsense>)
    <version>…</version>
    <system>
      <hostname>, <domain>, <timeservers>, <webgui>, <ssh>, <user>, …
    </system>
    <interfaces><wan>, <lan>, …</interfaces>
    <filter><rule>, …</filter>
    <ipsec><phase1>, <phase2>, …</ipsec>
    <syslog>…</syslog>
    <snmpd>…</snmpd>
  </pfsense>
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from fireaudit.parsers.base import BaseParser, infer_interface_role


# ---------------------------------------------------------------------------
# ElementTree helpers (copied pattern from paloalto parser)
# ---------------------------------------------------------------------------

def _text(el: ET.Element | None, path: str, default: str | None = None) -> str | None:
    if el is None:
        return default
    node = el.find(path)
    return node.text.strip() if (node is not None and node.text) else default


def _bool_tag(el: ET.Element | None, path: str) -> bool:
    """Return True if the tag exists and is not explicitly 'false'/'0'/'disabled'."""
    if el is None:
        return False
    node = el.find(path)
    if node is None:
        return False
    text = (node.text or "").strip().lower()
    return text not in ("false", "0", "disabled", "no", "disable")


def _exists(el: ET.Element | None, path: str) -> bool:
    """Return True if element exists at path."""
    if el is None:
        return False
    return el.find(path) is not None


def _int(el: ET.Element | None, path: str) -> int | None:
    val = _text(el, path)
    if val is None:
        return None
    try:
        return int(val)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class PfSenseParser(BaseParser):
    """Parser for pfSense and OPNsense config.xml files."""

    vendor = "pfsense"

    # pfSense uses <pfsense> root; OPNsense uses <opnsense>
    SUPPORTED_ROOTS = {"pfsense", "opnsense"}

    def parse(self, content: str) -> dict:
        try:
            root = ET.fromstring(content)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid XML: {exc}") from exc

        if root.tag not in self.SUPPORTED_ROOTS:
            raise ValueError(
                f"Unexpected root element <{root.tag}>. Expected one of {self.SUPPORTED_ROOTS}"
            )

        # Detect OPNsense vs pfSense
        if root.tag == "opnsense":
            self.vendor = "opnsense"

        ir = self._base_ir()
        ir["meta"]["vendor"] = self.vendor

        system = root.find("system")
        interfaces = root.find("interfaces")
        filter_el = root.find("filter")
        ipsec = root.find("ipsec")
        syslog = root.find("syslog")
        snmpd = root.find("snmpd")
        openvpn = root.find("openvpn")

        self._extract_meta(root, system, ir)
        self._extract_admin_access(system, snmpd, ir)
        self._extract_authentication(system, ir)
        self._extract_logging(system, syslog, ir)
        self._extract_vpn(ipsec, openvpn, ir)
        self._extract_firewall_policies(filter_el, ir)
        self._extract_interfaces(interfaces, ir)

        return ir

    # ------------------------------------------------------------------
    # Section extractors
    # ------------------------------------------------------------------

    def _extract_meta(self, root: ET.Element, system: ET.Element | None, ir: dict) -> None:
        version = _text(root, "version") or _text(system, "version")
        ir["meta"]["firmware_version"] = version
        ir["meta"]["hostname"] = _text(system, "hostname")
        # Domain
        domain = _text(system, "domain")
        if domain:
            hostname = ir["meta"]["hostname"] or ""
            if hostname and domain not in hostname:
                ir["meta"]["hostname"] = f"{hostname}.{domain}"

    def _extract_admin_access(self, system: ET.Element | None, snmpd: ET.Element | None, ir: dict) -> None:
        aa = ir["admin_access"]
        protocols: list[dict] = []

        # --- Web GUI (HTTPS/HTTP) ---
        webgui = system.find("webgui") if system is not None else None
        gui_proto = _text(webgui, "protocol") or "https"
        https_enabled = gui_proto.lower() == "https"
        http_enabled = gui_proto.lower() == "http"
        protocols.append({
            "protocol": "https",
            "enabled": https_enabled,
            "port": _int(webgui, "port") or 443,
            "interfaces": [],
            "version": None,
        })
        protocols.append({
            "protocol": "http",
            "enabled": http_enabled,
            "port": 80,
            "interfaces": [],
            "version": None,
        })
        aa["https_settings"]["enabled"] = https_enabled

        # TLS min version
        tls_min = _text(webgui, "ssl-certref")  # not TLS version, just cert ref
        # pfSense doesn't expose TLS min version directly in older versions

        # --- SSH ---
        ssh_el = system.find("ssh") if system is not None else None
        ssh_enabled = _exists(system, "ssh/enable") or _bool_tag(ssh_el, "enable") if ssh_el is not None else False
        ssh_port = _int(ssh_el, "port") if ssh_el is not None else 22
        # Key-only auth
        ssh_keyonly = _bool_tag(ssh_el, "sshdkeyonly") if ssh_el is not None else False
        # SSH agent forwarding or group
        protocols.append({
            "protocol": "ssh",
            "enabled": ssh_enabled,
            "port": ssh_port or 22,
            "interfaces": [],
            "version": "2",  # pfSense only supports SSHv2
        })
        aa["ssh_settings"]["enabled"] = ssh_enabled
        aa["ssh_settings"]["version"] = 2

        # --- Telnet: not supported by pfSense ---
        protocols.append({"protocol": "telnet", "enabled": False, "port": 23, "interfaces": [], "version": None})

        aa["management_protocols"] = protocols

        # --- Session timeout ---
        timeout = _int(system, "webgui/session-timeout") if system is not None else None
        if timeout is None:
            timeout = _int(system, "webgui/loginautocomplete")  # not quite but closest
        aa["session_timeout_seconds"] = timeout

        # --- Login protection (anti-brute-force) ---
        login_protection = _exists(system, "loginprotection")
        aa["max_login_attempts"] = 10 if login_protection else None  # default when enabled

        # --- SNMP ---
        # pfSense stores SNMP config in the top-level <snmpd> element.
        if snmpd is not None:
            snmp = aa["snmp"]
            snmp_enabled = _bool_tag(snmpd, "enable")
            snmp["enabled"] = snmp_enabled
            if snmp_enabled:
                rocommunity = _text(snmpd, "rocommunity")
                if rocommunity:
                    snmp["community_strings"] = [rocommunity]
                    snmp["version"] = "v2c"
                # pfSense does not natively support SNMPv3 without packages

        # --- Banner ---
        banner = _text(system, "motd") or _text(system, "loginprotection")
        aa["banner"] = banner
        aa["banner_enabled"] = banner is not None and banner not in ("", "loginprotection")

    def _extract_authentication(self, system: ET.Element | None, ir: dict) -> None:
        auth = ir["authentication"]

        # --- Local users ---
        users: list[dict] = []
        default_admin_exists = False

        if system is not None:
            for user_el in system.findall("user"):
                username = _text(user_el, "name") or ""
                if not username:
                    continue
                if username.lower() == "admin":
                    default_admin_exists = True

                scope = _text(user_el, "scope") or "local"
                group = _text(user_el, "groupname") or ""
                priv_level = "superuser" if group in ("admins", "wheel") else "user"

                # Password hash
                pwd = _text(user_el, "password") or _text(user_el, "bcrypt-hash") or ""
                hash_algo = None
                if pwd.startswith("$2y$") or pwd.startswith("$2b$") or pwd.startswith("$2a$"):
                    hash_algo = "bcrypt"
                elif pwd.startswith("$1$"):
                    hash_algo = "md5-crypt"
                elif pwd.startswith("$6$"):
                    hash_algo = "sha512-crypt"

                # MFA — check for totp/otp configured
                otp = _exists(user_el, "otp_seed") or _exists(user_el, "mfa")
                mfa_enabled = otp

                users.append({
                    "username": username,
                    "privilege_level": priv_level,
                    "mfa_enabled": mfa_enabled,
                    "password_hash_algorithm": hash_algo,
                    "account_enabled": _text(user_el, "disabled") is None,
                })

        auth["local_users"] = users
        auth["default_admin_account_exists"] = default_admin_exists
        auth["default_admin_renamed"] = not default_admin_exists

        # --- Password policy: pfSense doesn't have a central password policy in XML ---
        # Leave as None (not configured = not enforced)

        # --- RADIUS / LDAP auth servers ---
        ra = auth["remote_auth"]
        servers: list[dict] = []

        if system is not None:
            for authsrv in system.findall("authserver"):
                stype = _text(authsrv, "type") or ""
                host = _text(authsrv, "host") or ""
                if not host:
                    continue
                if "radius" in stype.lower():
                    ra["radius_enabled"] = True
                    servers.append({"type": "radius", "host": host, "port": _int(authsrv, "radius_auth_port") or 1812})
                elif "ldap" in stype.lower():
                    ra["ldap_enabled"] = True
                    port = _int(authsrv, "ldap_port")
                    servers.append({"type": "ldap", "host": host, "port": port or 389})

        ra["servers"] = servers

    def _extract_logging(
        self,
        system: ET.Element | None,
        syslog: ET.Element | None,
        ir: dict,
    ) -> None:
        log = ir["logging"]

        # --- NTP ---
        ntp_raw = _text(system, "timeservers") if system is not None else None
        ntp_servers: list[str] = []
        if ntp_raw:
            ntp_servers = [s.strip() for s in ntp_raw.split() if s.strip()]
        log["ntp_servers"] = ntp_servers
        log["ntp_enabled"] = len(ntp_servers) > 0

        # --- Syslog ---
        syslog_servers: list[dict] = []
        if syslog is not None:
            # pfSense supports up to 3 remote syslog servers
            for key in ("remoteserver", "remoteserver2", "remoteserver3"):
                host = _text(syslog, key)
                if host:
                    # Host may include port like "10.0.0.1:514"
                    port = 514
                    if ":" in host:
                        parts = host.rsplit(":", 1)
                        host = parts[0]
                        try:
                            port = int(parts[1])
                        except ValueError:
                            pass
                    syslog_servers.append({
                        "host": host,
                        "port": port,
                        "protocol": "udp",
                        "facility": None,
                        "severity": None,
                    })

            log["log_traffic"] = _bool_tag(syslog, "filter")
            log["log_authentication"] = _bool_tag(syslog, "auth")
            log["log_system_events"] = _bool_tag(syslog, "system")
            log["log_vpn"] = _bool_tag(syslog, "vpn")

        log["syslog_servers"] = syslog_servers
        log["local_logging_enabled"] = True  # Always logs locally

        # SNMP is passed separately; set in admin_access extraction via root caller
        # (callers pass snmpd element)

    def _extract_vpn(
        self,
        ipsec: ET.Element | None,
        openvpn: ET.Element | None,
        ir: dict,
    ) -> None:
        vpn = ir["vpn"]

        # --- IPsec ---
        tunnels: dict[str, dict] = {}  # ikeid -> tunnel

        if ipsec is not None:
            for p1 in ipsec.findall("phase1"):
                ikeid = _text(p1, "ikeid") or str(len(tunnels))
                descr = _text(p1, "descr") or f"tunnel-{ikeid}"
                disabled = _exists(p1, "disabled")

                enc_algo = _text(p1, "encryption-algorithm-option/name") or "aes"
                keylen = _text(p1, "encryption-algorithm-option/keylen")
                if keylen:
                    enc_algo = f"{enc_algo}{keylen}"
                hash_algo = _text(p1, "hash-algorithm-option") or "sha256"
                dh_group_raw = _text(p1, "dhgroup")
                dh_groups: list[int] = []
                if dh_group_raw:
                    try:
                        dh_groups = [int(dh_group_raw)]
                    except ValueError:
                        pass

                ike_type = _text(p1, "iketype") or "ikev1"
                ike_version = 2 if "v2" in ike_type.lower() or ike_type == "auto" else 1

                auth_method = _text(p1, "authentication_method") or "pre_shared_key"
                auth_map = {"pre_shared_key": "psk", "cert": "certificate", "eap-tls": "eap"}
                auth_method = auth_map.get(auth_method.lower(), "psk")

                mode = _text(p1, "mode") or "main"
                aggressive_mode = mode.lower() == "aggressive"

                tunnels[ikeid] = {
                    "name": descr,
                    "enabled": not disabled,
                    "remote_gateway": _text(p1, "remote-gateway"),
                    "phase1": {
                        "encryption": [enc_algo.lower()],
                        "authentication": [hash_algo.lower()],
                        "dh_groups": dh_groups,
                        "lifetime_seconds": _int(p1, "lifetime") or 28800,
                        "pfs_enabled": True,
                        "ike_version": ike_version,
                        "aggressive_mode": aggressive_mode,
                    },
                    "phase2": {
                        "encryption": [],
                        "authentication": [],
                        "dh_groups": [],
                        "lifetime_seconds": None,
                        "pfs_enabled": None,
                    },
                    "auth_method": auth_method,
                }

            for p2 in ipsec.findall("phase2"):
                ikeid = _text(p2, "ikeid")
                if ikeid and ikeid in tunnels:
                    enc_algo = _text(p2, "encryption-algorithm-option/name") or "aes"
                    keylen = _text(p2, "encryption-algorithm-option/keylen")
                    if keylen:
                        enc_algo = f"{enc_algo}{keylen}"
                    hash_algo = _text(p2, "hash-algorithm-option") or "sha256"
                    pfsgroup_raw = _text(p2, "pfsgroup")
                    pfs_groups: list[int] = []
                    if pfsgroup_raw and pfsgroup_raw != "0":
                        try:
                            pfs_groups = [int(pfsgroup_raw)]
                        except ValueError:
                            pass
                    tunnels[ikeid]["phase2"] = {
                        "encryption": [enc_algo.lower()],
                        "authentication": [hash_algo.lower()],
                        "dh_groups": pfs_groups,
                        "lifetime_seconds": _int(p2, "lifetime") or 3600,
                        "pfs_enabled": bool(pfs_groups),
                    }

        vpn["ipsec_tunnels"] = list(tunnels.values())

        # --- OpenVPN (maps to ssl_vpn) ---
        ssl_vpn = vpn["ssl_vpn"]
        if openvpn is not None:
            server_el = openvpn.find("openvpn-server")
            if server_el is not None:
                ssl_vpn["enabled"] = _text(server_el, "disable") is None
                # TLS version
                tls_ver = _text(server_el, "tls_type") or ""
                ssl_vpn["tls_versions"] = ["TLSv1.2", "TLSv1.3"]  # OpenVPN 2.5+ defaults
                # Cert required
                cert_depth = _text(server_el, "cert_depth")
                ssl_vpn["client_certificate_required"] = cert_depth is not None and cert_depth != "0"
                # Split tunnel
                no_default = _text(server_el, "local_network") or _text(server_el, "local_networkv6")
                ssl_vpn["split_tunneling"] = no_default is not None

    def _extract_firewall_policies(self, filter_el: ET.Element | None, ir: dict) -> None:
        policies: list[dict] = []
        if filter_el is None:
            ir["firewall_policies"] = policies
            return

        rule_idx = 0
        for rule in filter_el.findall("rule"):
            rule_idx += 1

            disabled = _exists(rule, "disabled")
            rule_type = _text(rule, "type") or "pass"
            action_map = {"pass": "allow", "block": "deny", "reject": "reject", "match": "inspect"}
            action = action_map.get(rule_type.lower(), "deny")

            # Source
            src_el = rule.find("source")
            src_addrs = self._parse_fw_addr(src_el)

            # Destination
            dst_el = rule.find("destination")
            dst_addrs = self._parse_fw_addr(dst_el)

            protocol = _text(rule, "protocol") or "any"

            # Interface (acts as zone/direction in pfSense)
            interface = _text(rule, "interface") or ""

            # Port ranges
            src_ports = []
            dst_ports = []
            if src_el is not None:
                p = _text(src_el, "port")
                if p and p != "any":
                    src_ports = [p]
            if dst_el is not None:
                p = _text(dst_el, "port")
                if p and p != "any":
                    dst_ports = [p]

            # Logging: pfSense has explicit <log/> tag
            logging_enabled = _exists(rule, "log")

            policies.append({
                "id": rule_idx,
                "name": _text(rule, "descr") or f"rule-{rule_idx}",
                "enabled": not disabled,
                "action": action,
                "source_zones": [interface] if interface else [],
                "destination_zones": [],
                "source_addresses": src_addrs,
                "destination_addresses": dst_addrs,
                "services": [protocol] if protocol and protocol != "any" else ["any"],
                "protocols": [protocol] if protocol else [],
                "source_ports": src_ports,
                "destination_ports": dst_ports,
                "logging_enabled": logging_enabled,
                "comment": _text(rule, "descr"),
                "schedule": _text(rule, "sched"),
                "nat_enabled": False,
            })

        ir["firewall_policies"] = policies

    def _parse_fw_addr(self, addr_el: ET.Element | None) -> list[str]:
        """Parse pfSense source/destination address element."""
        if addr_el is None:
            return ["any"]
        if addr_el.find("any") is not None:
            return ["all"]
        network = _text(addr_el, "network")
        if network:
            return [network]
        addr = _text(addr_el, "address")
        mask = _text(addr_el, "mask")
        if addr and mask:
            return [f"{addr}/{mask}"]
        if addr:
            return [addr]
        return ["any"]

    def _extract_interfaces(self, interfaces: ET.Element | None, ir: dict) -> None:
        iface_list: list[dict] = []
        if interfaces is None:
            ir["interfaces"] = iface_list
            return

        # Each child of <interfaces> is a named interface (wan, lan, opt1, etc.)
        for iface_el in list(interfaces):
            iface_logical_name = iface_el.tag  # "wan", "lan", "opt1", etc.
            if_name = _text(iface_el, "if") or iface_logical_name
            description = _text(iface_el, "descr") or iface_logical_name.upper()
            disabled = _exists(iface_el, "disabled")

            # IP address
            ip_type = _text(iface_el, "ipaddr") or ""
            ip_addr = None
            netmask = None
            if ip_type and ip_type not in ("dhcp", "pppoe", "ppp", "l2tp", "pptp"):
                ip_addr = ip_type
                netmask = _text(iface_el, "subnet")

            iface_list.append({
                "name": if_name,
                "type": _text(iface_el, "type") or "physical",
                "role": infer_interface_role(iface_logical_name, if_name),
                "zone": iface_logical_name,
                "ip_address": ip_addr,
                "netmask": netmask,
                "enabled": not disabled,
                "management_access": [],
                "description": description,
            })

        ir["interfaces"] = iface_list


# OPNsense uses the same structure with minor differences; reuse PfSenseParser
class OPNsenseParser(PfSenseParser):
    """Parser for OPNsense config.xml (same structure as pfSense with minor differences)."""

    vendor = "opnsense"
