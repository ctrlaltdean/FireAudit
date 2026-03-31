"""WatchGuard Firebox XML configuration parser.

Parses the XML policy backup exported from WatchGuard Firebox / Fireware devices
into the FireAudit normalised IR.

WatchGuard Fireware XML backup root structure::

  <policy os-version="12.10.0.B692988">  (some firmware versions use <profile> as root)
    <setup>
      <name>Firebox-01</name>
      <model-info>
        <model>M370</model>
        <serial-number>80AF20ABC1234</serial-number>
      </model-info>
      <admin>
        <admin-session-timeout>10</admin-session-timeout>
        <login-banner>…</login-banner>
      </admin>
      <feature-key>…</feature-key>
    </setup>
    <interface name="Trusted">…</interface>
    <interface name="External">…</interface>
    <authentication-server>…</authentication-server>
    <policy-tag name="…" type="packet-filter">…</policy-tag>
    <logging>
      <syslog-server>…</syslog-server>
    </logging>
    <ntp-client>…</ntp-client>
    <snmp>…</snmp>
    <user>…</user>
    <ipsec-tunnel>…</ipsec-tunnel>
    <mobile-user-vpn>…</mobile-user-vpn>
  </policy>
"""

from __future__ import annotations

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


def _int(el: ET.Element | None, path: str) -> int | None:
    """Return integer value of a child element, or None."""
    val = _text(el, path)
    if val is None:
        return None
    try:
        return int(val)
    except ValueError:
        return None


def _bool(el: ET.Element | None, path: str) -> bool | None:
    """Return True/False for a child element with text true/false/enabled/disabled/1/0."""
    val = _text(el, path)
    if val is None:
        return None
    return val.strip().lower() in ("true", "1", "enabled", "enable", "yes")


def _bool_attr(el: ET.Element | None, attr: str) -> bool | None:
    """Return boolean for an attribute value."""
    if el is None:
        return None
    val = el.get(attr)
    if val is None:
        return None
    return val.strip().lower() in ("true", "1", "enabled", "enable", "yes")


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _norm_encryption(raw: str) -> str:
    """Normalise encryption algorithm names to lowercase compact IR tokens."""
    mapping: dict[str, str] = {
        "AES-CBC-256": "aes256",
        "AES-CBC-192": "aes192",
        "AES-CBC-128": "aes128",
        "AES-GCM-256": "aes-gcm-256",
        "AES-GCM-128": "aes-gcm-128",
        "3DES-CBC":    "3des",
        "3DES":        "3des",
        "DES-CBC":     "des",
        "DES":         "des",
    }
    return mapping.get(raw.strip(), raw.strip().lower().replace("-", ""))


def _norm_hash(raw: str) -> str:
    """Normalise hash/auth algorithm names to lowercase IR tokens."""
    mapping: dict[str, str] = {
        "SHA2-512": "sha512",
        "SHA2-384": "sha384",
        "SHA2-256": "sha256",
        "SHA1":     "sha1",
        "MD5":      "md5",
        "HMAC-SHA2-512": "sha512",
        "HMAC-SHA2-256": "sha256",
        "HMAC-SHA1":     "sha1",
        "HMAC-MD5":      "md5",
    }
    return mapping.get(raw.strip(), raw.strip().lower())


def _norm_dh(raw: str | None) -> int | None:
    """Parse DH group from strings like '14', 'DH-14', 'MODP-2048'."""
    if raw is None:
        return None
    s = raw.strip().lstrip("DH").lstrip("-").lstrip("MODP").lstrip("-")
    # Special: MODP-2048 = group 14, MODP-1024 = group 2
    modp_map = {"2048": 14, "3072": 15, "4096": 16, "1024": 2}
    if s in modp_map:
        return modp_map[s]
    try:
        return int(s)
    except ValueError:
        return None


def _norm_action(raw: str) -> str:
    """Map WatchGuard policy actions to IR action tokens."""
    mapping: dict[str, str] = {
        "allow":   "allow",
        "allowed": "allow",
        "deny":    "deny",
        "denied":  "deny",
        "drop":    "deny",
        "blocked": "deny",
    }
    return mapping.get(raw.strip().lower(), "deny")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class WatchGuardParser(BaseParser):
    """Parser for WatchGuard Firebox / Fireware XML configuration backups."""

    vendor = "watchguard"

    def parse(self, content: str) -> dict:
        try:
            root = ET.fromstring(content)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid XML: {exc}") from exc

        if root.tag not in ("policy", "profile"):
            raise ValueError(
                f"Unexpected root element <{root.tag}>. Expected <policy> or <profile>"
            )

        # Detect old Fireware XML schema (X-series, pre-v11).
        # Old schema has <policy-list> as a direct child instead of the
        # v11+ children (<setup>, <interface>, <policy-tag>, <logging>, etc.).
        if root.find("policy-list") is not None:
            return self._parse_old_schema(root)

        ir = self._base_ir()

        self._extract_meta(root, ir)
        self._extract_admin_access(root, ir)
        self._extract_authentication(root, ir)
        self._extract_logging(root, ir)
        self._extract_vpn(root, ir)
        self._extract_firewall_policies(root, ir)
        self._extract_interfaces(root, ir)
        self._extract_network_objects(root, ir)

        return ir

    # ------------------------------------------------------------------
    # Legacy schema (pre-v11 / X-series) best-effort parser
    # ------------------------------------------------------------------

    def _parse_old_schema(self, root: ET.Element) -> dict:
        """Best-effort extraction from the old Fireware X-series XML schema.

        The old schema (pre-v11) uses different element names and structure
        compared to Fireware v11+.  We extract what is reasonably available
        so that rules can run against it instead of aborting with an error.
        Fields not present in the old format are left at their IR defaults.
        """
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "WatchGuard old Fireware schema (pre-v11) detected — "
            "partial extraction only; some audit checks may show N/A."
        )

        ir = self._base_ir()
        meta = ir["meta"]
        meta["vendor"] = self.vendor

        # Device identity — old schema uses <system-parameters><device-conf>
        sys_params = root.find("system-parameters")
        dev_conf = sys_params.find("device-conf") if sys_params is not None else None
        meta["hostname"] = _text(dev_conf, "system-name")

        # Model: <base-model> on root, or <for-model> inside device-conf
        model_val = _text(root, "base-model") or _text(dev_conf, "for-model")
        meta["model"] = model_val

        # Firmware / schema version: <for-version> on root
        meta["firmware_version"] = _text(root, "for-version")

        # Firewall policies — <policy-list><policy>
        policies: list[dict] = []
        for pol in root.findall("policy-list/policy"):
            name = _text(pol, "name") or ""
            enabled_raw = _text(pol, "enable")
            enabled = enabled_raw in (None, "1", "true")
            # <firewall>: 1 = allow/packet-filter, 0 = deny/blocked
            fw_raw = _text(pol, "firewall")
            action = "allow" if fw_raw in ("1", None) else "deny"
            log_raw = _text(pol, "log")
            has_log = log_raw not in (None, "0", "false")
            src = [a.text.strip() for a in pol.findall("from-alias-list/alias") if a.text]
            dst = [a.text.strip() for a in pol.findall("to-alias-list/alias") if a.text]
            svc = _text(pol, "service")
            policies.append({
                "name": name,
                "enabled": enabled,
                "action": action,
                "log": has_log,
                "source": src,
                "destination": dst,
                "service": svc or "Any",
                "comment": _text(pol, "description") or "",
            })
        ir["firewall_policies"] = policies

        # Interfaces — <interface-list><interface>
        interfaces: list[dict] = []
        for iface in root.findall("interface-list/interface"):
            name = _text(iface, "name") or ""
            if not name or name.startswith("Any"):
                continue  # skip pseudo-interfaces
            phys = iface.find(".//physical-if")
            ip_raw = _text(phys, "ip") if phys is not None else None
            mask_raw = _text(phys, "netmask") if phys is not None else None
            enabled_raw = _text(phys, "enabled") if phys is not None else None
            enabled = enabled_raw in (None, "1", "true")
            # Build CIDR if both IP and mask are present
            ip_cidr: str | None = None
            if ip_raw and mask_raw:
                try:
                    import ipaddress
                    net = ipaddress.IPv4Network(f"{ip_raw}/{mask_raw}", strict=False)
                    ip_cidr = f"{ip_raw}/{net.prefixlen}"
                except ValueError:
                    ip_cidr = ip_raw
            interfaces.append({
                "name": name,
                "ip_address": ip_cidr or ip_raw,
                "enabled": enabled,
                "zone": None,
                "role": infer_interface_role(None, name),
                "management_access": [],
                "description": _text(iface, "description") or "",
            })
        ir["interfaces"] = interfaces

        return ir

    # ------------------------------------------------------------------
    # Section extractors
    # ------------------------------------------------------------------

    def _extract_meta(self, root: ET.Element, ir: dict) -> None:
        meta = ir["meta"]
        meta["vendor"] = self.vendor

        os_ver = root.get("os-version")
        meta["firmware_version"] = os_ver.strip() if os_ver else None

        setup = root.find("setup")
        meta["hostname"] = _text(setup, "name")

        model_info = setup.find("model-info") if setup is not None else None
        if model_info is not None:
            meta["model"] = _text(model_info, "model")
            meta["serial_number"] = _text(model_info, "serial-number")
        else:
            meta["model"] = _text(setup, "model")
            meta["serial_number"] = _text(setup, "serial-number")

    def _extract_admin_access(self, root: ET.Element, ir: dict) -> None:
        aa = ir["admin_access"]

        setup = root.find("setup")
        admin_el = setup.find("admin") if setup is not None else None

        # --- Management protocols ---
        mgmt_el = admin_el.find("management-protocols") if admin_el is not None else None
        if mgmt_el is None:
            mgmt_el = root.find("management-protocols")
        https_en = _bool(mgmt_el, "https") if mgmt_el is not None else True
        if https_en is None:
            https_en = True
        http_en = _bool(mgmt_el, "http") if mgmt_el is not None else False
        if http_en is None:
            http_en = False
        ssh_en = _bool(mgmt_el, "ssh") if mgmt_el is not None else True
        if ssh_en is None:
            ssh_en = True
        telnet_en = _bool(mgmt_el, "telnet") if mgmt_el is not None else False
        if telnet_en is None:
            telnet_en = False

        https_port_val = _int(admin_el, "https-port") or _int(mgmt_el, "https-port") or 8080
        ssh_port_val = _int(admin_el, "ssh-port") or 22

        aa["management_protocols"] = [
            {"protocol": "https",  "enabled": https_en,  "port": https_port_val, "interfaces": [], "version": None},
            {"protocol": "http",   "enabled": http_en,   "port": 80,  "interfaces": [], "version": None},
            {"protocol": "ssh",    "enabled": ssh_en,    "port": ssh_port_val,   "interfaces": [], "version": "2"},
            {"protocol": "telnet", "enabled": telnet_en, "port": 23,  "interfaces": [], "version": None},
        ]

        aa["https_settings"]["enabled"] = https_en

        # --- TLS ---
        tls_el = (admin_el.find("tls") if admin_el is not None else None) or root.find("tls-settings")
        tls_min_raw = _text(tls_el, "min-version") or _text(admin_el, "min-tls-version")
        if tls_min_raw:
            ver = tls_min_raw.strip()
            # Normalise "TLS 1.2" -> "TLSv1.2"
            if " " in ver and ver.upper().startswith("TLS"):
                ver = "TLSv" + ver.split()[-1]
            elif ver.upper().startswith("TLSV"):
                ver = "TLSv" + ver[4:]
            aa["https_settings"]["tls_versions"] = [ver]

        # --- SSH ---
        aa["ssh_settings"]["enabled"] = ssh_en
        aa["ssh_settings"]["version"] = 2

        # --- Session timeout ---
        timeout_raw = _int(admin_el, "admin-session-timeout")
        aa["session_timeout_seconds"] = timeout_raw * 60 if timeout_raw is not None else None

        # --- Login / lockout policy ---
        aa["max_login_attempts"] = _int(admin_el, "max-login-attempts") or _int(setup, "max-login-attempts")
        lockout_raw = _int(admin_el, "lockout-period")
        aa["lockout_duration_seconds"] = lockout_raw * 60 if lockout_raw is not None else None

        # --- Banner ---
        banner = _text(admin_el, "login-banner") or _text(setup, "login-banner")
        aa["banner"] = banner
        aa["banner_enabled"] = bool(banner)

        # --- Trusted hosts ---
        hosts: list[str] = []
        trusted_el = admin_el.find("trusted-hosts") if admin_el is not None else None
        if trusted_el is None:
            trusted_el = root.find("trusted-management-hosts")
        if trusted_el is not None:
            for h in trusted_el.findall("host"):
                val = (h.text or "").strip() or h.get("ip", "")
                if val:
                    hosts.append(val)
        aa["trusted_hosts"] = hosts

        # --- SNMP ---
        snmp_el = root.find("snmp")
        if snmp_el is not None:
            enabled_val = _bool(snmp_el, "enabled")
            if enabled_val is None:
                enabled_val = snmp_el.get("enabled", "false").lower() not in ("false", "0", "no")
            aa["snmp"]["enabled"] = bool(enabled_val)
            ver_raw = _text(snmp_el, "version")
            if ver_raw:
                aa["snmp"]["version"] = ver_raw
            community = _text(snmp_el, "community-string")
            if community:
                aa["snmp"]["community_strings"] = [community]
            # SNMPv3 security level
            v3_el = snmp_el.find("v3") or snmp_el.find("snmpv3")
            if v3_el is not None:
                has_auth = v3_el.find("auth") is not None or _text(v3_el, "auth-algorithm") is not None
                has_priv = v3_el.find("priv") is not None or _text(v3_el, "priv-algorithm") is not None
                if has_auth and has_priv:
                    aa["snmp"]["security_level"] = "auth-priv"
                elif has_auth:
                    aa["snmp"]["security_level"] = "auth-no-priv"
                else:
                    aa["snmp"]["security_level"] = "no-auth-no-priv"

    def _extract_authentication(self, root: ET.Element, ir: dict) -> None:
        auth = ir["authentication"]
        setup = root.find("setup")

        # --- Password policy ---
        pp = auth["password_policy"]
        pw_el = (
            root.find("password-policy")
            or (setup.find("password-policy") if setup is not None else None)
        )
        if pw_el is not None:
            pp["min_length"] = _int(pw_el, "min-length")
            pp["max_age_days"] = _int(pw_el, "max-age")
            pp["history_count"] = _int(pw_el, "history")
            pp["lockout_threshold"] = _int(pw_el, "lockout-threshold")
            complexity_val = _bool(pw_el, "complexity-enabled")
            if complexity_val:
                pp["require_uppercase"] = True
                pp["require_lowercase"] = True
                pp["require_numbers"] = True
                pp["require_special"] = True

        # --- Local users ---
        users: list[dict] = []
        default_admin_exists = False
        for user_el in root.findall("user"):
            username = _text(user_el, "name") or user_el.get("name", "")
            if not username:
                continue
            if username.lower() == "admin":
                default_admin_exists = True
            role_raw = (_text(user_el, "role") or _text(user_el, "type") or "user").lower()
            is_admin = role_raw in ("admin", "superuser", "device-admin", "device admin")
            mfa_val = _bool(user_el, "two-factor-auth") or _bool(user_el, "mfa-enabled")
            enabled_val = _bool(user_el, "enabled")
            if enabled_val is None:
                enabled_val = True

            users.append({
                "username": username,
                "privilege_level": "superuser" if is_admin else "user",
                "mfa_enabled": bool(mfa_val) if mfa_val is not None else False,
                "password_hash_algorithm": None,
                "account_enabled": enabled_val,
            })

        auth["local_users"] = users
        auth["default_admin_account_exists"] = default_admin_exists
        auth["default_admin_renamed"] = not default_admin_exists

        # --- Remote auth servers ---
        ra = auth["remote_auth"]
        servers: list[dict] = []

        for auth_server in root.findall("authentication-server"):
            type_raw = (_text(auth_server, "type") or auth_server.get("type", "")).lower()
            host = _text(auth_server, "server-ip") or _text(auth_server, "ip")
            if not host:
                continue
            if "radius" in type_raw:
                port = _int(auth_server, "port") or 1812
                servers.append({"type": "radius", "host": host, "port": port})
            elif "tacacs" in type_raw:
                port = _int(auth_server, "port") or 49
                servers.append({"type": "tacacs+", "host": host, "port": port})
            elif "ldap" in type_raw or "active-directory" in type_raw:
                port = _int(auth_server, "port") or 389
                servers.append({"type": "ldap", "host": host, "port": port})

        ra["servers"] = servers
        ra["radius_enabled"] = any(s["type"] == "radius" for s in servers)
        ra["tacacs_enabled"] = any(s["type"] == "tacacs+" for s in servers)
        ra["ldap_enabled"] = any(s["type"] in ("ldap", "ldaps") for s in servers)

    def _extract_logging(self, root: ET.Element, ir: dict) -> None:
        log = ir["logging"]

        # --- Syslog ---
        syslog_servers: list[dict] = []
        logging_el = root.find("logging")
        if logging_el is not None:
            for srv_el in logging_el.findall("syslog-server"):
                host = _text(srv_el, "ip") or _text(srv_el, "server-ip") or (srv_el.get("ip") or "")
                if not host:
                    continue
                port_val = _int(srv_el, "port") or 514
                proto_raw = (_text(srv_el, "protocol") or "udp").lower()
                syslog_servers.append({
                    "host": host,
                    "port": port_val,
                    "protocol": proto_raw,
                    "facility": _text(srv_el, "facility"),
                    "severity": _text(srv_el, "severity"),
                })

        log["syslog_servers"] = syslog_servers
        log["local_logging_enabled"] = bool(logging_el is not None)

        # --- NTP ---
        ntp_el = root.find("ntp-client")
        if ntp_el is None:
            ntp_el = root.find("ntp")
        ntp_servers: list[str] = []
        ntp_enabled = False
        if ntp_el is not None:
            ntp_enabled_val = _bool(ntp_el, "enabled")
            ntp_enabled = bool(ntp_enabled_val)
            for key in ("server", "server1", "server2", "ntp-server"):
                for el in ntp_el.findall(key):
                    val = (el.text or "").strip() or el.get("ip", "")
                    if val:
                        ntp_servers.append(val)
        log["ntp_servers"] = ntp_servers
        log["ntp_enabled"] = ntp_enabled

    def _extract_vpn(self, root: ET.Element, ir: dict) -> None:
        vpn = ir["vpn"]

        # --- IPsec tunnels (branch office VPN) ---
        tunnels: list[dict] = []
        for tunnel_el in root.findall("ipsec-tunnel"):
            name = _text(tunnel_el, "name") or tunnel_el.get("name", f"tunnel-{len(tunnels)+1}")
            enabled_val = _bool(tunnel_el, "enabled")
            if enabled_val is None:
                enabled_val = True

            gateway_el = tunnel_el.find("gateway")
            if gateway_el is None:
                gateway_el = tunnel_el
            remote_gw = _text(gateway_el, "remote-ip") or _text(gateway_el, "peer-ip")

            auth_raw = (_text(gateway_el, "auth-method") or "pre-shared-key").lower()
            auth_method = "psk" if "pre-shared" in auth_raw or "psk" in auth_raw else "certificate"

            ike_raw = _text(gateway_el, "ike-version") or _text(tunnel_el, "ike-version") or "2"
            try:
                ike_version: int = int(ike_raw)
            except ValueError:
                ike_version = 2

            # Phase 1 (IKE SA)
            p1_el = tunnel_el.find("phase1")
            if p1_el is None:
                p1_el = tunnel_el.find("ike-sa")
            p1_enc_raw = _text(p1_el, "encryption")
            p1_hash_raw = _text(p1_el, "hash") or _text(p1_el, "authentication")
            p1_dh_raw = _text(p1_el, "dh-group")
            p1_life = _int(p1_el, "lifetime") or 28800
            p1_dh = _norm_dh(p1_dh_raw)

            mode_raw = (_text(p1_el, "mode") or _text(gateway_el, "mode") or "main").lower()
            aggressive_mode = "aggressive" in mode_raw and ike_version == 1
            phase1: dict[str, Any] = {
                "encryption": [_norm_encryption(p1_enc_raw)] if p1_enc_raw else [],
                "authentication": [_norm_hash(p1_hash_raw)] if p1_hash_raw else [],
                "dh_groups": [p1_dh] if p1_dh is not None else [],
                "lifetime_seconds": p1_life,
                "pfs_enabled": True,
                "ike_version": ike_version,
                "aggressive_mode": aggressive_mode,
            }

            # Phase 2 (IPsec SA)
            p2_el = tunnel_el.find("phase2")
            if p2_el is None:
                p2_el = tunnel_el.find("ipsec-sa")
            p2_enc_raw = _text(p2_el, "encryption")
            p2_hash_raw = _text(p2_el, "hash") or _text(p2_el, "authentication")
            p2_dh_raw = _text(p2_el, "dh-group") or (_text(p2_el, "pfs-group") if p2_el is not None else None)
            p2_life = _int(p2_el, "lifetime") or 3600
            pfs_val = _bool(p2_el, "pfs-enabled") if p2_el is not None else None
            p2_dh = _norm_dh(p2_dh_raw)

            phase2: dict[str, Any] = {
                "encryption": [_norm_encryption(p2_enc_raw)] if p2_enc_raw else [],
                "authentication": [_norm_hash(p2_hash_raw)] if p2_hash_raw else [],
                "dh_groups": [p2_dh] if p2_dh is not None else [],
                "lifetime_seconds": p2_life,
                "pfs_enabled": pfs_val if pfs_val is not None else True,
            }

            tunnels.append({
                "name": name,
                "enabled": enabled_val,
                "remote_gateway": remote_gw,
                "phase1": phase1,
                "phase2": phase2,
                "auth_method": auth_method,
            })

        vpn["ipsec_tunnels"] = tunnels

        # --- Mobile user VPN (SSL/SSLVPN) ---
        ssl_vpn = vpn["ssl_vpn"]
        mvpn_el = root.find("mobile-user-vpn")
        if mvpn_el is None:
            mvpn_el = root.find("ssl-vpn")
        if mvpn_el is not None:
            enabled_val = _bool(mvpn_el, "enabled")
            if enabled_val is None:
                enabled_val = True
            ssl_vpn["enabled"] = enabled_val
            tls_min_raw = _text(mvpn_el, "min-tls-version") or _text(mvpn_el, "tls-min-version")
            if tls_min_raw:
                ver = tls_min_raw.strip()
                if " " in ver and ver.upper().startswith("TLS"):
                    ver = "TLSv" + ver.split()[-1]
                elif not ver.upper().startswith("TLSV"):
                    ver = "TLSv" + ver
                ssl_vpn["tls_versions"] = [ver]
            cert_req = _bool(mvpn_el, "client-cert-required")
            ssl_vpn["client_certificate_required"] = bool(cert_req) if cert_req is not None else False
            split = _bool(mvpn_el, "split-tunneling")
            ssl_vpn["split_tunneling"] = split

    def _extract_firewall_policies(self, root: ET.Element, ir: dict) -> None:
        policies: list[dict] = []
        rule_idx = 0

        for policy_el in root.findall("policy-tag"):
            rule_idx += 1
            name = policy_el.get("name") or _text(policy_el, "name") or f"rule-{rule_idx}"
            enabled_val = _bool_attr(policy_el, "enabled")
            if enabled_val is None:
                enabled_val = _bool(policy_el, "enabled")
            if enabled_val is None:
                enabled_val = True

            action_raw = policy_el.get("action") or _text(policy_el, "action") or "deny"
            action = _norm_action(action_raw)

            # Source / destination
            from_zone = _text(policy_el, "from-zone") or ""
            to_zone = _text(policy_el, "to-zone") or ""

            src_el = policy_el.find("sources")
            dst_el = policy_el.find("destinations")

            if src_el is not None:
                src_list = [
                    (m.text or m.get("name", "")).strip()
                    for m in src_el.findall("member")
                    if (m.text or "").strip() or m.get("name")
                ]
                if not src_list:
                    src_list = ["any"]
            else:
                src_raw = _text(policy_el, "source") or "any"
                src_list = ["any"] if src_raw.lower() == "any" else [src_raw]

            if dst_el is not None:
                dst_list = [
                    (m.text or m.get("name", "")).strip()
                    for m in dst_el.findall("member")
                    if (m.text or "").strip() or m.get("name")
                ]
                if not dst_list:
                    dst_list = ["any"]
            else:
                dst_raw = _text(policy_el, "destination") or "any"
                dst_list = ["any"] if dst_raw.lower() == "any" else [dst_raw]

            # Services
            svc_el = policy_el.find("services")
            if svc_el is not None:
                svc_list = [
                    (m.text or m.get("name", "")).strip()
                    for m in svc_el.findall("member")
                    if (m.text or "").strip() or m.get("name")
                ]
                if not svc_list:
                    svc_list = ["any"]
            else:
                svc_raw = _text(policy_el, "service") or "any"
                svc_list = ["any"] if svc_raw.lower() == "any" else [svc_raw]

            log_val = _bool(policy_el, "log-enabled")
            if log_val is None:
                log_val = _bool_attr(policy_el, "log")
            if log_val is None:
                log_val = True

            policies.append({
                "id": rule_idx,
                "name": name,
                "enabled": enabled_val,
                "action": action,
                "source_zones": [from_zone] if from_zone else [],
                "destination_zones": [to_zone] if to_zone else [],
                "source_addresses": src_list,
                "destination_addresses": dst_list,
                "services": svc_list,
                "protocols": [],
                "source_ports": [],
                "destination_ports": [],
                "logging_enabled": log_val,
                "comment": _text(policy_el, "description") or _text(policy_el, "comment"),
                "schedule": _text(policy_el, "schedule"),
                "nat_enabled": False,
            })

        ir["firewall_policies"] = policies

    def _extract_interfaces(self, root: ET.Element, ir: dict) -> None:
        ifaces: list[dict] = []

        for iface_el in root.findall("interface"):
            name = iface_el.get("name") or _text(iface_el, "name") or ""
            if not name:
                continue

            zone = _text(iface_el, "zone") or iface_el.get("type") or ""

            # IP address — may be in <ip-address>10.0.0.1/24</ip-address> or separate
            ip_raw = _text(iface_el, "ip-address") or _text(iface_el, "ip")
            if ip_raw and "/" in ip_raw:
                ip_addr, netmask = ip_raw.split("/", 1)
            else:
                ip_addr = ip_raw
                netmask = _text(iface_el, "netmask") or _text(iface_el, "subnet-mask")

            enabled_val = _bool(iface_el, "enabled")
            if enabled_val is None:
                enabled_val = True

            mgmt_access: list[str] = []
            mgmt_el = iface_el.find("management-access")
            if mgmt_el is not None:
                if _bool(mgmt_el, "https"):
                    mgmt_access.append("https")
                if _bool(mgmt_el, "ssh"):
                    mgmt_access.append("ssh")
                if _bool(mgmt_el, "ping"):
                    mgmt_access.append("ping")

            ifaces.append({
                "name": name,
                "type": "ethernet",
                "role": infer_interface_role(zone, name),
                "zone": zone,
                "ip_address": ip_addr,
                "netmask": netmask,
                "enabled": enabled_val,
                "management_access": mgmt_access,
                "description": _text(iface_el, "description"),
            })

        ir["interfaces"] = ifaces

    def _extract_network_objects(self, root: ET.Element, ir: dict) -> None:
        address_objects: list[dict] = []
        service_objects: list[dict] = []

        for obj_el in root.findall("address-object"):
            name = obj_el.get("name") or _text(obj_el, "name") or ""
            if not name:
                continue
            type_raw = (_text(obj_el, "type") or obj_el.get("type") or "host").lower()
            type_map = {
                "host": "host",
                "network": "network",
                "range": "range",
                "fqdn": "fqdn",
                "group": "group",
            }
            obj_type = type_map.get(type_raw, "host")
            if obj_type == "network":
                ip = _text(obj_el, "ip-address") or _text(obj_el, "ip")
                mask = _text(obj_el, "netmask") or _text(obj_el, "subnet-mask")
                value = f"{ip}/{mask}" if ip and mask else ip
            elif obj_type == "range":
                start = _text(obj_el, "start-ip")
                end = _text(obj_el, "end-ip")
                value = f"{start}-{end}" if start and end else start
            elif obj_type == "fqdn":
                value = _text(obj_el, "fqdn")
            else:
                value = _text(obj_el, "ip-address") or _text(obj_el, "ip")
            address_objects.append({"name": name, "type": obj_type, "value": value})

        for svc_el in root.findall("service-object"):
            name = svc_el.get("name") or _text(svc_el, "name") or ""
            if not name:
                continue
            proto = (_text(svc_el, "protocol") or "tcp").lower()
            port = _text(svc_el, "port") or _text(svc_el, "dest-port")
            service_objects.append({"name": name, "protocol": proto, "port_range": port})

        ir["network_objects"]["address_objects"] = address_objects
        ir["network_objects"]["service_objects"] = service_objects
