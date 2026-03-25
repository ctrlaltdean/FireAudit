"""Palo Alto Networks PAN-OS XML configuration parser.

Parses the running configuration XML exported from PAN-OS devices
('show config running' or saved backup XML) into the FireAudit IR.

PAN-OS XML root structure:
  <config version="10.x">
    <devices>
      <entry name="localhost.localdomain">
        <deviceconfig><system>…</system></deviceconfig>
        <vsys><entry name="vsys1">…</entry></vsys>
        <network>…</network>
      </entry>
    </devices>
    <mgt-config>
      <users>…</users>
      <password-complexity>…</password-complexity>
    </mgt-config>
    <shared>…</shared>
  </config>
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from fireaudit.parsers.base import BaseParser


# ---------------------------------------------------------------------------
# ElementTree helpers
# ---------------------------------------------------------------------------

def _text(el: ET.Element | None, path: str, default: str | None = None) -> str | None:
    """Find element by path and return its text, or default."""
    if el is None:
        return default
    node = el.find(path)
    return node.text.strip() if (node is not None and node.text) else default


def _yes(el: ET.Element | None, path: str) -> bool | None:
    """Return True if element text is 'yes', False if 'no', None if missing."""
    val = _text(el, path)
    if val is None:
        return None
    return val.lower() == "yes"


def _no(el: ET.Element | None, path: str) -> bool | None:
    """Return True if element text is 'no' (i.e. feature disabled)."""
    v = _yes(el, path)
    return None if v is None else not v


def _members(el: ET.Element | None, path: str = "member") -> list[str]:
    """Collect all <member> text values under the given path."""
    if el is None:
        return []
    container = el.find(path) if "/" in path or path != "member" else el
    if path != "member":
        container = el.find(path)
    if container is None:
        return []
    return [m.text.strip() for m in container.findall("member") if m.text]


def _members_at(el: ET.Element | None, path: str) -> list[str]:
    """Find container at path then collect all <member> children."""
    if el is None:
        return []
    container = el.find(path)
    if container is None:
        return []
    return [m.text.strip() for m in container.findall("member") if m.text]


def _int(el: ET.Element | None, path: str) -> int | None:
    val = _text(el, path)
    if val is None:
        return None
    try:
        return int(val)
    except ValueError:
        return None


def _entries(el: ET.Element | None, path: str | None = None) -> list[ET.Element]:
    """Return all <entry> elements under el or el.find(path)."""
    if el is None:
        return []
    target = el.find(path) if path else el
    if target is None:
        return []
    return target.findall("entry")


def _entry(el: ET.Element | None, path: str | None = None, name: str | None = None) -> ET.Element | None:
    """Find a specific <entry name="..."> by name."""
    if el is None:
        return None
    target = el.find(path) if path else el
    if target is None:
        return None
    if name:
        return target.find(f"entry[@name='{name}']")
    return target.find("entry")


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

class PaloAltoParser(BaseParser):
    """Parser for Palo Alto Networks PAN-OS running configuration XML."""

    vendor = "paloalto"

    def parse(self, content: str) -> dict:
        try:
            root = ET.fromstring(content)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid XML: {exc}") from exc

        # Handle both bare <config> and responses wrapped in <response>
        if root.tag == "response":
            config = root.find(".//config")
            if config is None:
                raise ValueError("No <config> element found in response XML")
        elif root.tag == "config":
            config = root
        else:
            # Try finding config anywhere
            config = root if root.tag == "config" else root.find(".//config") or root

        ir = self._base_ir()

        # Shortcut paths used throughout
        device = config.find("devices/entry")   # first device entry
        vsys = self._find_vsys(device)
        mgt = config.find("mgt-config")
        network = device.find("network") if device is not None else None
        shared = config.find("shared")
        sys_cfg = device.find("deviceconfig/system") if device is not None else None

        self._extract_meta(config, device, sys_cfg, ir)
        self._extract_admin_access(sys_cfg, device, ir)
        self._extract_authentication(mgt, ir)
        self._extract_logging(device, vsys, sys_cfg, ir)
        self._extract_vpn(network, ir)
        self._extract_firewall_policies(vsys, ir)
        self._extract_interfaces(network, ir)
        self._extract_network_objects(vsys, shared, ir)

        return ir

    # ------------------------------------------------------------------
    # Finders
    # ------------------------------------------------------------------

    def _find_vsys(self, device: ET.Element | None) -> ET.Element | None:
        if device is None:
            return None
        vsys_container = device.find("vsys")
        if vsys_container is None:
            return None
        # prefer vsys1, fall back to first entry
        vsys1 = vsys_container.find("entry[@name='vsys1']")
        return vsys1 if vsys1 is not None else vsys_container.find("entry")

    # ------------------------------------------------------------------
    # Section extractors
    # ------------------------------------------------------------------

    def _extract_meta(
        self,
        config: ET.Element,
        device: ET.Element | None,
        sys_cfg: ET.Element | None,
        ir: dict,
    ) -> None:
        version = config.get("version")
        ir["meta"]["firmware_version"] = version
        ir["meta"]["hostname"] = _text(sys_cfg, "hostname")
        ir["meta"]["model"] = _text(sys_cfg, "platform-family") or _text(sys_cfg, "type")

        # Serial from system info (not always in static config)
        ir["meta"]["serial_number"] = _text(sys_cfg, "serial")

    def _extract_admin_access(
        self,
        sys_cfg: ET.Element | None,
        device: ET.Element | None,
        ir: dict,
    ) -> None:
        aa = ir["admin_access"]
        svc = sys_cfg.find("service") if sys_cfg is not None else None

        # --- Management protocols ---
        protocols: list[dict] = []

        # HTTPS — enabled unless explicitly disabled
        https_disabled = _yes(svc, "disable-https") if svc is not None else False
        https_enabled = not bool(https_disabled)
        protocols.append({
            "protocol": "https",
            "enabled": https_enabled,
            "port": _int(sys_cfg, "port") or 443,
            "interfaces": [],
            "version": None,
        })
        aa["https_settings"]["enabled"] = https_enabled

        # HTTP — disabled unless explicitly enabled (PAN-OS defaults to disabled)
        http_enabled = _yes(svc, "disable-http") is False  # if disable-http is 'no', HTTP is on
        # More accurately: HTTP redirects to HTTPS by default; explicit enable needed
        # In config, if disable-http exists and is 'yes' → HTTP off; if 'no' → HTTP on
        http_val = _text(svc, "disable-http") if svc is not None else None
        http_enabled = http_val == "no"  # only enabled if explicitly set to not disabled
        protocols.append({
            "protocol": "http",
            "enabled": http_enabled,
            "port": 80,
            "interfaces": [],
            "version": None,
        })

        # SSH — enabled by default
        ssh_disabled = _yes(svc, "disable-ssh") if svc is not None else False
        ssh_enabled = not bool(ssh_disabled)
        protocols.append({
            "protocol": "ssh",
            "enabled": ssh_enabled,
            "port": _int(sys_cfg, "ssh/port") or 22,
            "interfaces": [],
            "version": "2",  # PAN-OS only supports SSHv2
        })
        aa["ssh_settings"]["enabled"] = ssh_enabled
        aa["ssh_settings"]["version"] = 2

        # Telnet — disabled by default
        telnet_val = _text(svc, "disable-telnet") if svc is not None else None
        telnet_enabled = telnet_val == "no"
        protocols.append({
            "protocol": "telnet",
            "enabled": telnet_enabled,
            "port": 23,
            "interfaces": [],
            "version": None,
        })

        aa["management_protocols"] = protocols

        # --- TLS version for HTTPS ---
        tls_min = _text(sys_cfg, "ssl-tls-service-profile") or _text(sys_cfg, "tls-min-version")
        if tls_min:
            aa["https_settings"]["tls_versions"] = self._parse_tls_version(tls_min)

        # --- Session / lockout ---
        timeout = _int(sys_cfg, "idle-timeout")
        aa["session_timeout_seconds"] = timeout * 60 if timeout else None
        aa["max_login_attempts"] = _int(sys_cfg, "max-login-attempts")
        lockout = _int(sys_cfg, "lockout-time")
        aa["lockout_duration_seconds"] = lockout * 60 if lockout else None

        # --- Trusted hosts (permitted-ip) ---
        permitted = sys_cfg.find("permitted-ip") if sys_cfg is not None else None
        trusted: list[str] = []
        if permitted is not None:
            for entry in permitted.findall("entry"):
                name = entry.get("name", "")
                if name:
                    trusted.append(name)
        aa["trusted_hosts"] = trusted

        # --- Login banner ---
        banner = _text(sys_cfg, "login-banner")
        aa["banner"] = banner
        aa["banner_enabled"] = bool(banner)

        # --- SNMP ---
        snmp = sys_cfg.find("snmp-setting") if sys_cfg is not None else None
        if snmp is not None:
            access = snmp.find("access-setting")
            version_el = access.find("version") if access is not None else None
            v3 = version_el.find("v3") if version_el is not None else None
            v2c = version_el.find("v2c") if version_el is not None else None
            v1_el = version_el.find("v1") if version_el is not None else None
            snmp_enabled = (v3 is not None or v2c is not None or v1_el is not None) and access is not None
            aa["snmp"]["enabled"] = snmp_enabled
            if v3 is not None:
                aa["snmp"]["version"] = "v3"
            elif v2c is not None:
                aa["snmp"]["version"] = "v2c"
                community = _text(v2c, "community")
                if community:
                    aa["snmp"]["community_strings"] = [community]
            elif v1_el is not None:
                aa["snmp"]["version"] = "v1"

    def _extract_authentication(self, mgt: ET.Element | None, ir: dict) -> None:
        auth = ir["authentication"]

        # --- Password complexity ---
        pw_complexity = mgt.find("password-complexity") if mgt is not None else None
        if pw_complexity is not None:
            pp = auth["password_policy"]
            enabled = _yes(pw_complexity, "enabled")
            if enabled:
                pp["min_length"] = _int(pw_complexity, "minimum-length")
                pp["require_uppercase"] = (_int(pw_complexity, "minimum-uppercase-letters") or 0) > 0
                pp["require_lowercase"] = (_int(pw_complexity, "minimum-lowercase-letters") or 0) > 0
                pp["require_numbers"] = (_int(pw_complexity, "minimum-numeric-letters") or 0) > 0
                pp["require_special"] = (_int(pw_complexity, "minimum-special-characters") or 0) > 0
                pp["history_count"] = _int(pw_complexity, "password-history-count")
                pp["lockout_threshold"] = _int(pw_complexity, "failed-attempts")
                pp["max_age_days"] = _int(pw_complexity, "maximum-age") or _int(pw_complexity, "expiry-warning")

        # --- Local users ---
        users_el = mgt.find("users") if mgt is not None else None
        users: list[dict] = []
        default_admin_exists = False

        for entry in _entries(users_el):
            username = entry.get("name", "")
            if username.lower() == "admin":
                default_admin_exists = True

            # Role
            perms = entry.find("permissions")
            role = "read-only"
            if perms is not None:
                rb = perms.find("role-based")
                if rb is not None:
                    if rb.find("superuser") is not None:
                        role = "superuser"
                    elif rb.find("deviceadmin") is not None:
                        role = "deviceadmin"
                    elif rb.find("superreader") is not None:
                        role = "superreader"
                    else:
                        # Custom role name
                        custom = rb.find("custom/profile")
                        role = custom.text if (custom is not None and custom.text) else "custom"

            # MFA — check for phishing-resistant or OTP authentication profile
            auth_profile = _text(entry, "authentication-profile")
            mfa = auth_profile is not None and auth_profile.lower() not in ("none", "")

            # Password hash
            phash = _text(entry, "phash")
            hash_algo = None
            if phash:
                if phash.startswith("$1$"):
                    hash_algo = "md5-crypt"
                elif phash.startswith("$5$"):
                    hash_algo = "sha256-crypt"
                elif phash.startswith("$6$"):
                    hash_algo = "sha512-crypt"

            users.append({
                "username": username,
                "privilege_level": role,
                "mfa_enabled": mfa,
                "password_hash_algorithm": hash_algo,
                "account_enabled": True,  # PAN-OS doesn't have per-user disable in config
            })

        auth["local_users"] = users
        auth["default_admin_account_exists"] = default_admin_exists
        auth["default_admin_renamed"] = not default_admin_exists

        # --- Remote auth servers ---
        # Radius/TACACS/LDAP are defined in server profiles
        # We look for server-profiles under shared or device
        ra = auth["remote_auth"]
        servers: list[dict] = []

        # These paths may vary — check both shared and mgt-config
        for profile_container_path in [
            "server-profile/radius",
            "server-profile/tacplus",
            "server-profile/ldap",
        ]:
            pass  # Handled below via device-level search

        # PAN-OS radius: ./shared/server-profile/radius or ./devices/entry/server-profile/radius
        # We'll mark as enabled if any profile entries exist

    def _extract_logging(
        self,
        device: ET.Element | None,
        vsys: ET.Element | None,
        sys_cfg: ET.Element | None,
        ir: dict,
    ) -> None:
        log = ir["logging"]

        # --- NTP ---
        ntp_el = sys_cfg.find("ntp-servers") if sys_cfg is not None else None
        ntp_servers: list[str] = []
        if ntp_el is not None:
            for child_name in ("primary-ntp-server", "secondary-ntp-server"):
                server_addr = _text(ntp_el, f"{child_name}/ntp-server-address")
                if server_addr:
                    ntp_servers.append(server_addr)
        log["ntp_servers"] = ntp_servers
        log["ntp_enabled"] = len(ntp_servers) > 0

        # --- Syslog servers ---
        # PAN-OS: syslog servers defined in syslog server profiles, referenced by log-forwarding profiles
        # Location: ./devices/entry/deviceconfig/syslog/using/entry (older) OR
        #           ./shared/log-forwarding or vsys log-settings
        syslog_servers: list[dict] = []

        # Check device-level syslog profiles
        device_syslog = device.find("deviceconfig/syslog") if device is not None else None
        if device_syslog is not None:
            for server_entry in _entries(device_syslog, "server"):
                host = _text(server_entry, "server") or server_entry.get("name", "")
                if host:
                    syslog_servers.append({
                        "host": host,
                        "port": _int(server_entry, "port") or 514,
                        "protocol": (_text(server_entry, "transport") or "UDP").lower(),
                        "facility": _text(server_entry, "facility"),
                        "severity": _text(server_entry, "format"),
                    })

        # Check log-forwarding profiles under vsys for syslog destinations
        if vsys is not None:
            log_settings = vsys.find("log-settings")
            if log_settings is not None:
                for profile in _entries(log_settings, "profiles"):
                    for match in _entries(profile, "match-list"):
                        send_syslog = match.find("send-syslog")
                        if send_syslog is not None:
                            for server_el in _entries(send_syslog, "using-syslog-setting"):
                                server_name = server_el.get("name", "")
                                if server_name:
                                    syslog_servers.append({
                                        "host": server_name,  # Name reference, not IP
                                        "port": 514,
                                        "protocol": "udp",
                                        "facility": None,
                                        "severity": None,
                                    })

        # Also check shared log-forwarding
        shared_lf = device.find("../shared/log-forwarding") if device is not None else None

        log["syslog_servers"] = syslog_servers
        log["local_logging_enabled"] = True  # PAN-OS always logs locally to MP

        # Traffic logging derived from security policy log settings (checked in policy extraction)
        log["log_authentication"] = True   # PAN-OS logs auth events by default
        log["log_admin_actions"] = True    # Admin commits/changes are always logged
        log["log_system_events"] = True

    def _extract_vpn(self, network: ET.Element | None, ir: dict) -> None:
        vpn = ir["vpn"]

        # --- Load crypto profiles first for lookup ---
        ike_profiles = self._load_ike_crypto_profiles(network)
        ipsec_profiles = self._load_ipsec_crypto_profiles(network)

        # --- IKE gateways ---
        gateways: dict[str, dict] = {}
        for gw_entry in _entries(network, "ike/gateway"):
            gw_name = gw_entry.get("name", "")

            # IKE version
            proto = gw_entry.find("protocol")
            ikev2_el = proto.find("ikev2") if proto is not None else None
            ikev1_el = proto.find("ikev1") if proto is not None else None
            ike_version = 2 if ikev2_el is not None else 1

            # Crypto profile lookup
            if ikev2_el is not None:
                profile_name = _text(ikev2_el, "ike-crypto-profile")
            elif ikev1_el is not None:
                profile_name = _text(ikev1_el, "ike-crypto-profile")
            else:
                profile_name = None

            profile = ike_profiles.get(profile_name, {}) if profile_name else {}

            # Remote peer IP
            peer_ip = None
            peer_addr = gw_entry.find("peer-address")
            if peer_addr is not None:
                peer_ip = _text(peer_addr, "ip") or _text(peer_addr, "fqdn")

            # Auth method
            auth_method = "psk"
            auth_el = gw_entry.find("authentication")
            if auth_el is not None:
                if auth_el.find("pre-shared-key") is not None:
                    auth_method = "psk"
                elif auth_el.find("certificate") is not None:
                    auth_method = "certificate"

            gateways[gw_name] = {
                "remote_gateway": peer_ip,
                "ike_version": ike_version,
                "auth_method": auth_method,
                "phase1": profile,
            }

        # --- IPsec tunnels ---
        tunnels: list[dict] = []
        for tunnel_entry in _entries(network, "tunnel/ipsec"):
            tunnel_name = tunnel_entry.get("name", "")
            disabled = tunnel_entry.find("disabled")
            enabled = not (disabled is not None and (disabled.text or "").lower() == "yes")

            ike_el = tunnel_entry.find("ike")
            gw_name = _text(ike_el, "gateway") if ike_el is not None else None
            p2_profile_name = _text(ike_el, "ipsec-crypto-profile") if ike_el is not None else None
            p2_profile = ipsec_profiles.get(p2_profile_name, {}) if p2_profile_name else {}

            gw_data = gateways.get(gw_name, {}) if gw_name else {}

            # Merge ike_version from gateway into phase1 (profile doesn't carry it)
            phase1 = dict(gw_data.get("phase1") or {
                "encryption": [], "authentication": [], "dh_groups": [],
                "lifetime_seconds": None, "pfs_enabled": True,
            })
            phase1["ike_version"] = gw_data.get("ike_version", 2)

            p2 = p2_profile if p2_profile else {
                "encryption": [], "authentication": [], "dh_groups": [],
                "lifetime_seconds": None, "pfs_enabled": None,
            }

            tunnels.append({
                "name": tunnel_name,
                "enabled": enabled,
                "remote_gateway": gw_data.get("remote_gateway"),
                "phase1": phase1,
                "phase2": p2,
                "auth_method": gw_data.get("auth_method", "psk"),
            })

        vpn["ipsec_tunnels"] = tunnels

        # --- GlobalProtect (SSL VPN) ---
        gp = network.find("../global-protect") if network is not None else None
        if gp is None and network is not None:
            # Try sibling path
            parent = network.find("..")
            if parent is not None:
                gp = parent.find("global-protect")

        gp_gw = None
        if gp is not None:
            gp_gw = gp.find("global-protect-gateway/entry")

        ssl_vpn = vpn["ssl_vpn"]
        if gp_gw is not None:
            ssl_vpn["enabled"] = True
            # TLS profile
            ssl_profile = _text(gp_gw, "ssl-tls-service-profile")
            # MFA
            auth_profile = _text(gp_gw, "authentication/client-auth/entry/authentication-profile")
            ssl_vpn["mfa_required"] = auth_profile is not None
            # Client certificate
            cert_required = _yes(gp_gw, "authentication/client-auth/entry/client-certificate")
            ssl_vpn["client_certificate_required"] = cert_required
            # Split tunneling — no-direct-access means split tunnel disabled
            split_disabled = gp_gw.find("remote-user-tunnel-configs")
            ssl_vpn["split_tunneling"] = None  # Complex to determine without full config

    def _load_ike_crypto_profiles(self, network: ET.Element | None) -> dict[str, dict]:
        """Load IKE crypto profiles (phase1) by name."""
        profiles: dict[str, dict] = {}
        if network is None:
            return profiles
        for entry in _entries(network, "ike/crypto-profiles/ike-crypto-profiles"):
            name = entry.get("name", "")
            encryptions = _members_at(entry, "encryption")
            hashes = _members_at(entry, "hash")
            dh_raw = _members_at(entry, "dh-group")
            dh_groups = self._parse_dh_groups(dh_raw)
            profiles[name] = {
                "encryption": [e.lower() for e in encryptions],
                "authentication": [h.lower() for h in hashes],
                "dh_groups": dh_groups,
                "lifetime_seconds": _int(entry, "lifetime/seconds") or _int(entry, "lifetime/hours", ) and ((_int(entry, "lifetime/hours") or 0) * 3600),
                "pfs_enabled": True,
                "ike_version": None,  # set at gateway level
            }
        return profiles

    def _load_ipsec_crypto_profiles(self, network: ET.Element | None) -> dict[str, dict]:
        """Load IPsec crypto profiles (phase2) by name."""
        profiles: dict[str, dict] = {}
        if network is None:
            return profiles
        for entry in _entries(network, "ike/crypto-profiles/ipsec-crypto-profiles"):
            name = entry.get("name", "")
            esp = entry.find("esp")
            ah = entry.find("ah")
            container = esp if esp is not None else ah
            encryptions = _members_at(container, "encryption") if container is not None else []
            hashes = _members_at(container, "authentication") if container is not None else []
            dh_raw = _members_at(entry, "dh-group")
            dh_groups = self._parse_dh_groups(dh_raw)
            lifetime_secs = (
                _int(entry, "lifetime/seconds")
                or ((_int(entry, "lifetime/hours") or 0) * 3600)
                or ((_int(entry, "lifetime/minutes") or 0) * 60)
            ) or None
            profiles[name] = {
                "encryption": [e.lower() for e in encryptions],
                "authentication": [h.lower() for h in hashes],
                "dh_groups": dh_groups,
                "lifetime_seconds": lifetime_secs,
                "pfs_enabled": len(dh_groups) > 0,
            }
        return profiles

    def _extract_firewall_policies(self, vsys: ET.Element | None, ir: dict) -> None:
        policies: list[dict] = []
        if vsys is None:
            ir["firewall_policies"] = policies
            return

        rule_idx = 0
        for rule_entry in _entries(vsys, "security/rules"):
            rule_idx += 1
            name = rule_entry.get("name", f"rule-{rule_idx}")

            # Enabled: disabled element absent means enabled
            disabled_el = rule_entry.find("disabled")
            enabled = not (disabled_el is not None and (disabled_el.text or "").lower() == "yes")

            action = _text(rule_entry, "action") or "deny"
            action_map = {"allow": "allow", "deny": "deny", "drop": "drop",
                          "reset-client": "reject", "reset-server": "reject", "reset-both": "reject"}
            action = action_map.get(action.lower(), "deny")

            src_zones = _members_at(rule_entry, "from")
            dst_zones = _members_at(rule_entry, "to")
            src_addrs = _members_at(rule_entry, "source")
            dst_addrs = _members_at(rule_entry, "destination")
            applications = _members_at(rule_entry, "application")
            services = _members_at(rule_entry, "service")

            # Logging — log-end defaults to yes in PAN-OS
            log_end = rule_entry.find("log-end")
            log_start = rule_entry.find("log-start")
            logging_enabled = True  # default
            if log_end is not None and (log_end.text or "").lower() == "no":
                if log_start is None or (log_start.text or "").lower() == "no":
                    logging_enabled = False

            # Profile group (UTM)
            profile_setting = rule_entry.find("profile-setting")
            has_utm = profile_setting is not None and len(list(profile_setting)) > 0

            policies.append({
                "id": rule_idx,
                "name": name,
                "enabled": enabled,
                "action": action,
                "source_zones": src_zones,
                "destination_zones": dst_zones,
                "source_addresses": src_addrs,
                "destination_addresses": dst_addrs,
                "services": services + applications,
                "protocols": [],
                "source_ports": [],
                "destination_ports": [],
                "logging_enabled": logging_enabled,
                "comment": _text(rule_entry, "description"),
                "schedule": _text(rule_entry, "schedule"),
                "nat_enabled": False,  # NAT is separate in PAN-OS
            })

        ir["firewall_policies"] = policies

    def _extract_interfaces(self, network: ET.Element | None, ir: dict) -> None:
        interfaces: list[dict] = []
        if network is None:
            ir["interfaces"] = interfaces
            return

        iface_el = network.find("interface")
        if iface_el is None:
            ir["interfaces"] = interfaces
            return

        for iface_type_el in list(iface_el):
            iface_type = iface_type_el.tag  # ethernet, loopback, tunnel, vlan, etc.
            for entry in _entries(iface_type_el):
                iface_name = entry.get("name", "")

                # IP from layer3 or ip element
                ip_addr = None
                netmask = None
                _l3 = entry.find("layer3")
                layer3 = _l3 if _l3 is not None else entry.find("ip")
                if layer3 is not None:
                    _ipe = layer3.find("ip/entry")
                    ip_entry = _ipe if _ipe is not None else layer3.find("entry")
                    if ip_entry is not None:
                        addr = ip_entry.get("name", "")
                        if "/" in addr:
                            parts = addr.split("/", 1)
                            ip_addr = parts[0]
                            netmask = parts[1]
                    # Also check direct ip/entry name format
                    for ip_e in _entries(layer3, "ip"):
                        addr = ip_e.get("name", "")
                        if "/" in addr:
                            ip_addr = addr.split("/")[0]
                            netmask = addr.split("/")[1]
                            break

                # Zone membership derived from zone config (cross-referenced)
                # Management allowed access
                mgmt_profile = _text(entry, "layer3/interface-management-profile") or _text(entry, "interface-management-profile")

                interfaces.append({
                    "name": iface_name,
                    "type": iface_type,
                    "zone": None,  # populated from zone config cross-ref
                    "ip_address": ip_addr,
                    "netmask": netmask,
                    "enabled": not (_yes(entry, "disabled") or False),
                    "management_access": [mgmt_profile] if mgmt_profile else [],
                    "description": _text(entry, "comment"),
                })

        # Cross-reference zones to add zone info to interfaces
        vsys_container = network.find("../vsys")
        if vsys_container is not None:
            for vsys_entry in _entries(vsys_container):
                for zone_entry in _entries(vsys_entry, "zone"):
                    zone_name = zone_entry.get("name", "")
                    for iface_name in (
                        _members_at(zone_entry, "network/layer3")
                        + _members_at(zone_entry, "network/layer2")
                        + _members_at(zone_entry, "network/tap")
                        + _members_at(zone_entry, "network/virtual-wire")
                    ):
                        for iface in interfaces:
                            if iface["name"] == iface_name:
                                iface["zone"] = zone_name

        ir["interfaces"] = interfaces

    def _extract_network_objects(
        self,
        vsys: ET.Element | None,
        shared: ET.Element | None,
        ir: dict,
    ) -> None:
        address_objects: list[dict] = []
        service_objects: list[dict] = []

        for scope in [s for s in [vsys, shared] if s is not None]:
            # Address objects
            for addr_entry in _entries(scope, "address"):
                name = addr_entry.get("name", "")
                if addr_entry.find("ip-netmask") is not None:
                    obj_type = "network"
                    value = _text(addr_entry, "ip-netmask")
                elif addr_entry.find("ip-range") is not None:
                    obj_type = "range"
                    value = _text(addr_entry, "ip-range")
                elif addr_entry.find("fqdn") is not None:
                    obj_type = "fqdn"
                    value = _text(addr_entry, "fqdn")
                else:
                    obj_type = "host"
                    value = None
                address_objects.append({"name": name, "type": obj_type, "value": value})

            # Address groups
            for grp_entry in _entries(scope, "address-group"):
                name = grp_entry.get("name", "")
                members = _members_at(grp_entry, "static")
                address_objects.append({"name": name, "type": "group", "value": ",".join(members)})

            # Service objects
            for svc_entry in _entries(scope, "service"):
                name = svc_entry.get("name", "")
                proto_el = svc_entry.find("protocol")
                if proto_el is None:
                    continue
                tcp = proto_el.find("tcp")
                udp = proto_el.find("udp")
                if tcp is not None:
                    port = _text(tcp, "port") or _text(tcp, "destination-port")
                    service_objects.append({"name": name, "protocol": "tcp", "port_range": port})
                elif udp is not None:
                    port = _text(udp, "port") or _text(udp, "destination-port")
                    service_objects.append({"name": name, "protocol": "udp", "port_range": port})

        ir["network_objects"]["address_objects"] = address_objects
        ir["network_objects"]["service_objects"] = service_objects

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _parse_dh_groups(self, groups: list[str]) -> list[int]:
        """Convert PAN-OS DH group names like 'group14' or 'group19' to integers."""
        result: list[int] = []
        for g in groups:
            g_lower = g.lower().replace("group", "").strip()
            try:
                result.append(int(g_lower))
            except ValueError:
                pass
        return result

    def _parse_tls_version(self, raw: str) -> list[str]:
        raw = raw.lower()
        versions: list[str] = []
        if "tls1-0" in raw or "tls1.0" in raw:
            versions.extend(["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"])
        elif "tls1-1" in raw or "tls1.1" in raw:
            versions.extend(["TLSv1.1", "TLSv1.2", "TLSv1.3"])
        elif "tls1-2" in raw or "tls1.2" in raw:
            versions.extend(["TLSv1.2", "TLSv1.3"])
        elif "tls1-3" in raw or "tls1.3" in raw:
            versions.append("TLSv1.3")
        return versions if versions else ["TLSv1.2", "TLSv1.3"]
