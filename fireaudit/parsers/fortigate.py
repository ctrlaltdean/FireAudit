"""FortiGate .conf parser.

Parses FortiOS configuration files (exported via 'show full-configuration'
or 'show') into the normalized FireAudit IR.

FortiGate config structure uses a hierarchical block format:
    config <section>
        edit <id|name>
            set <key> <value>
            config <subsection>
                ...
            end
        next
    end
"""

from __future__ import annotations

import re
from typing import Any

from fireaudit.parsers.base import BaseParser


# ---------------------------------------------------------------------------
# Low-level config parser
# ---------------------------------------------------------------------------

class _FGBlock:
    """Represents a parsed FortiGate config block."""

    def __init__(self, name: str = "root") -> None:
        self.name = name
        self.entries: dict[str, "_FGBlock"] = {}   # edit id/name -> block
        self.settings: dict[str, str | list[str]] = {}   # set key -> value
        self.children: dict[str, "_FGBlock"] = {}  # config <section> -> block


def _tokenize(content: str) -> list[str]:
    """Split FortiGate config into tokens, preserving quoted strings."""
    tokens: list[str] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Tokenize respecting quotes
        for tok in re.findall(r'"[^"]*"|\S+', line):
            tokens.append(tok.strip('"'))
    return tokens


def _parse_block(tokens: list[str], pos: int) -> tuple[_FGBlock, int]:
    """Recursively parse a block starting after 'config <name>' has been consumed."""
    block = _FGBlock()
    current_entry: _FGBlock | None = None

    while pos < len(tokens):
        tok = tokens[pos]

        if tok == "end":
            pos += 1
            break

        elif tok == "next":
            current_entry = None
            pos += 1

        elif tok == "config":
            # Nested config section
            pos += 1
            section_parts = []
            while pos < len(tokens) and tokens[pos] not in ("edit", "set", "end", "next", "config", "unset", "delete", "append", "rename"):
                section_parts.append(tokens[pos])
                pos += 1
            section_name = " ".join(section_parts)
            child_block, pos = _parse_block(tokens, pos)
            child_block.name = section_name
            target = current_entry if current_entry is not None else block
            target.children[section_name] = child_block

        elif tok == "edit":
            pos += 1
            entry_id = tokens[pos] if pos < len(tokens) else "unknown"
            pos += 1
            current_entry = _FGBlock(name=entry_id)
            block.entries[entry_id] = current_entry

        elif tok == "set":
            pos += 1
            if pos >= len(tokens):
                break
            key = tokens[pos]
            pos += 1
            values: list[str] = []
            while pos < len(tokens) and tokens[pos] not in ("set", "config", "edit", "next", "end", "unset", "delete", "append", "rename"):
                values.append(tokens[pos])
                pos += 1
            value: str | list[str] = values[0] if len(values) == 1 else values
            target = current_entry if current_entry is not None else block
            target.settings[key] = value

        elif tok in ("unset", "delete", "append", "rename"):
            # Skip to next meaningful token
            pos += 1
            while pos < len(tokens) and tokens[pos] not in ("set", "config", "edit", "next", "end", "unset", "delete", "append", "rename"):
                pos += 1

        else:
            pos += 1

    return block, pos


def _parse_config(content: str) -> dict[str, _FGBlock]:
    """Parse full FortiGate config file into top-level sections."""
    tokens = _tokenize(content)
    pos = 0
    sections: dict[str, _FGBlock] = {}

    while pos < len(tokens):
        tok = tokens[pos]
        if tok == "config":
            pos += 1
            section_parts = []
            while pos < len(tokens) and tokens[pos] not in ("edit", "set", "end", "next", "config"):
                section_parts.append(tokens[pos])
                pos += 1
            section_name = " ".join(section_parts)
            block, pos = _parse_block(tokens, pos)
            block.name = section_name
            sections[section_name] = block
        else:
            pos += 1

    return sections


# ---------------------------------------------------------------------------
# IR extraction helpers
# ---------------------------------------------------------------------------

def _get(block: _FGBlock, key: str, default: Any = None) -> Any:
    return block.settings.get(key, default)


def _enabled(block: _FGBlock, key: str) -> bool | None:
    val = _get(block, key)
    if val is None:
        return None
    return str(val).lower() in ("enable", "enabled", "yes", "true", "1")


def _int_val(block: _FGBlock, key: str) -> int | None:
    val = _get(block, key)
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _list_val(block: _FGBlock, key: str) -> list[str]:
    val = _get(block, key)
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v) for v in val]
    return [str(val)]


# ---------------------------------------------------------------------------
# Main parser class
# ---------------------------------------------------------------------------

class FortiGateParser(BaseParser):
    """Parser for FortiGate .conf files (FortiOS)."""

    vendor = "fortigate"

    # Weak ciphers and deprecated algorithms
    WEAK_CIPHERS = {"3des", "des", "rc4", "null", "aes128-cbc", "aes192-cbc"}
    WEAK_DH_GROUPS = {1, 2, 5}
    WEAK_HASHES = {"md5", "sha1"}

    def parse(self, content: str) -> dict:
        sections = _parse_config(content)
        ir = self._base_ir()

        self._extract_meta(sections, ir)
        self._extract_admin_access(sections, ir)
        self._extract_authentication(sections, ir)
        self._extract_logging(sections, ir)
        self._extract_vpn(sections, ir)
        self._extract_firewall_policies(sections, ir)
        self._extract_interfaces(sections, ir)
        self._extract_network_objects(sections, ir)

        return ir

    # ------------------------------------------------------------------
    # Section extractors
    # ------------------------------------------------------------------

    def _extract_meta(self, sections: dict[str, _FGBlock], ir: dict) -> None:
        sys_global = sections.get("system global", _FGBlock())
        ir["meta"]["hostname"] = _get(sys_global, "hostname")
        ir["meta"]["firmware_version"] = _get(sys_global, "firmware-version")

        # Try version comment at top of file (captured as settings on root)
        # FortiGate files often begin with: #config-version=FGVMXXXX-x.x.x...
        # This is handled by comment extraction below if needed.

    def _extract_admin_access(self, sections: dict[str, _FGBlock], ir: dict) -> None:
        sys_global = sections.get("system global", _FGBlock())
        aa = ir["admin_access"]

        # Session timeout
        timeout = _int_val(sys_global, "admintimeout")
        aa["session_timeout_seconds"] = timeout * 60 if timeout else None

        # Max login attempts & lockout
        aa["max_login_attempts"] = _int_val(sys_global, "admin-lockout-threshold") or _int_val(sys_global, "admin-login-max")
        lockout = _int_val(sys_global, "admin-lockout-duration")
        aa["lockout_duration_seconds"] = lockout

        # Banner
        banner = _get(sys_global, "pre-login-banner") or _get(sys_global, "post-login-banner")
        aa["banner"] = banner
        aa["banner_enabled"] = banner is not None and banner.lower() not in ("disable", "none", "")

        # Management protocols — parse system interface for allowed access
        # and system settings for global protocol toggles
        protocols: list[dict] = []

        # SSH
        ssh_block = sections.get("system ssh", _FGBlock())
        ssh_enabled = _get(sys_global, "admin-ssh") != "disable"
        ssh_version_raw = _get(ssh_block, "ssh-policy-check") or _get(sys_global, "admin-ssh-v1")
        ssh_version = 1 if ssh_version_raw and "v1" in str(ssh_version_raw).lower() else 2
        protocols.append({"protocol": "ssh", "enabled": ssh_enabled, "port": _int_val(sys_global, "admin-ssh-port") or 22, "interfaces": [], "version": str(ssh_version)})
        aa["ssh_settings"]["enabled"] = ssh_enabled
        aa["ssh_settings"]["version"] = ssh_version

        # HTTPS
        https_enabled = _get(sys_global, "admin-https") != "disable"
        protocols.append({"protocol": "https", "enabled": https_enabled, "port": _int_val(sys_global, "admin-https-port") or 443, "interfaces": [], "version": None})
        aa["https_settings"]["enabled"] = https_enabled

        # HTTP (should be disabled)
        http_enabled = _get(sys_global, "admin-http") == "enable"
        protocols.append({"protocol": "http", "enabled": http_enabled, "port": _int_val(sys_global, "admin-http-port") or 80, "interfaces": [], "version": None})

        # Telnet
        telnet_enabled = _get(sys_global, "admin-telnet") == "enable"
        protocols.append({"protocol": "telnet", "enabled": telnet_enabled, "port": 23, "interfaces": [], "version": None})

        # TLS version for HTTPS/SSL
        tls_min = _get(sys_global, "admin-https-ssl-versions") or _get(sys_global, "ssl-min-proto-version")
        if tls_min:
            tls_versions = self._parse_tls_versions(str(tls_min))
            aa["https_settings"]["tls_versions"] = tls_versions

        aa["management_protocols"] = protocols

        # SNMP
        snmp_block = sections.get("system snmp sysinfo", _FGBlock())
        snmp_community_block = sections.get("system snmp community", _FGBlock())
        snmp_user_block = sections.get("system snmp user", _FGBlock())
        snmp_enabled = _enabled(snmp_block, "status")
        aa["snmp"]["enabled"] = bool(snmp_enabled)

        communities = []
        for _entry_id, entry in snmp_community_block.entries.items():
            name = _get(entry, "name")
            if name:
                communities.append(str(name))
        aa["snmp"]["community_strings"] = communities

        # SNMPv3 security level: check if any v3 user is configured and what level it uses
        # FortiGate: 'config system snmp user' → 'set security-level auth-priv|auth-no-priv|no-auth-no-priv'
        if snmp_user_block.entries:
            aa["snmp"]["version"] = "v3"
            # Find the weakest security level across all v3 users
            level_rank = {"auth-priv": 3, "auth-no-priv": 2, "no-auth-no-priv": 1}
            weakest = None
            for _uid, u_entry in snmp_user_block.entries.items():
                lvl = _get(u_entry, "security-level") or "no-auth-no-priv"
                rank = level_rank.get(str(lvl).lower(), 1)
                if weakest is None or rank < level_rank.get(weakest, 0):
                    weakest = str(lvl).lower()
            aa["snmp"]["security_level"] = weakest
        elif communities:
            # Has community strings but no v3 users → v1/v2c
            aa["snmp"]["version"] = "v2c"
            aa["snmp"]["security_level"] = None

        # Trusted hosts for admin accounts (populated from system admin section)
        trusted: list[str] = []
        admin_section = sections.get("system admin", _FGBlock())
        for _uid, admin_entry in admin_section.entries.items():
            for i in range(1, 7):
                th = _get(admin_entry, f"trusthost{i}")
                if th and isinstance(th, list):
                    trusted.append("/".join(th))
                elif th:
                    trusted.append(str(th))
        aa["trusted_hosts"] = list(set(trusted))

    def _extract_authentication(self, sections: dict[str, _FGBlock], ir: dict) -> None:
        auth = ir["authentication"]
        sys_global = sections.get("system global", _FGBlock())

        # Password policy
        pp = auth["password_policy"]
        pp["min_length"] = _int_val(sys_global, "admin-password-minimum-length")
        policy_str = _get(sys_global, "admin-password-policy")

        pw_policy_block = sections.get("system password-policy", _FGBlock())
        if pw_policy_block.settings:
            pp["min_length"] = pp["min_length"] or _int_val(pw_policy_block, "minimum-length")
            pp["require_uppercase"] = _enabled(pw_policy_block, "must-contain") and "uppercase" in str(_get(pw_policy_block, "must-contain", "")).lower()
            pp["require_lowercase"] = _enabled(pw_policy_block, "must-contain") and "lowercase" in str(_get(pw_policy_block, "must-contain", "")).lower()
            pp["require_numbers"] = _enabled(pw_policy_block, "must-contain") and ("digit" in str(_get(pw_policy_block, "must-contain", "")).lower() or "number" in str(_get(pw_policy_block, "must-contain", "")).lower())
            pp["require_special"] = _enabled(pw_policy_block, "must-contain") and "special" in str(_get(pw_policy_block, "must-contain", "")).lower()
            pp["max_age_days"] = _int_val(pw_policy_block, "expire-day")
            pp["history_count"] = _int_val(pw_policy_block, "reuse-password")
            expire_status = _get(pw_policy_block, "expire-status")
            if expire_status == "disable":
                pp["max_age_days"] = None

        # Lockout policy
        pp["lockout_threshold"] = _int_val(sys_global, "admin-lockout-threshold")

        # Local admin accounts
        admin_section = sections.get("system admin", _FGBlock())
        users: list[dict] = []
        default_admin_exists = False
        default_admin_renamed = True

        for username, entry in admin_section.entries.items():
            if username.lower() == "admin":
                default_admin_exists = True
                default_admin_renamed = False

            accprofile = _get(entry, "accprofile") or ""
            priv = "super_admin" if accprofile in ("super_admin", "super-admin") else accprofile

            passwd_hash = _get(entry, "password")
            hash_algo = None
            if passwd_hash:
                ps = str(passwd_hash)
                if ps.startswith("$1$"):
                    hash_algo = "md5"
                elif ps.startswith("$5$"):
                    hash_algo = "sha256"
                elif ps.startswith("$6$"):
                    hash_algo = "sha512"
                elif ps.startswith("ENC"):
                    hash_algo = "fortigate_enc"

            two_factor_val = _get(entry, "two-factor")
            mfa = two_factor_val is not None and str(two_factor_val).lower() not in ("disable", "none", "false", "0")
            users.append({
                "username": username,
                "privilege_level": priv,
                "mfa_enabled": mfa,
                "password_hash_algorithm": hash_algo,
                "account_enabled": _get(entry, "status") != "disable",
            })

        auth["local_users"] = users
        auth["default_admin_account_exists"] = default_admin_exists
        auth["default_admin_renamed"] = default_admin_renamed

        # Remote auth
        radius_block = sections.get("user radius", _FGBlock())
        tacacs_block = sections.get("user tacacs+", _FGBlock())
        ldap_block = sections.get("user ldap", _FGBlock())

        remote = auth["remote_auth"]
        remote["radius_enabled"] = len(radius_block.entries) > 0
        remote["tacacs_enabled"] = len(tacacs_block.entries) > 0
        remote["ldap_enabled"] = len(ldap_block.entries) > 0

        servers: list[dict] = []
        for _uid, entry in radius_block.entries.items():
            server = _get(entry, "server")
            if server:
                servers.append({"type": "radius", "host": str(server), "port": _int_val(entry, "auth-port") or 1812})
        for _uid, entry in tacacs_block.entries.items():
            server = _get(entry, "server")
            if server:
                servers.append({"type": "tacacs+", "host": str(server), "port": _int_val(entry, "port") or 49})
        for _uid, entry in ldap_block.entries.items():
            server = _get(entry, "server")
            if server:
                servers.append({"type": "ldap", "host": str(server), "port": _int_val(entry, "port") or 389})
        remote["servers"] = servers

    def _extract_logging(self, sections: dict[str, _FGBlock], ir: dict) -> None:
        log = ir["logging"]

        # Syslog servers — FortiGate supports up to 4: log syslogd/2/3/4 setting
        syslog_servers: list[dict] = []
        for suffix in ("", "2", "3", "4"):
            section_name = f"log syslogd{suffix} setting"
            sl = sections.get(section_name, _FGBlock())
            status = _get(sl, "status")
            server = _get(sl, "server")
            if server and status != "disable":
                proto = _get(sl, "mode") or "udp"
                syslog_servers.append({
                    "host": str(server),
                    "port": _int_val(sl, "port") or 514,
                    "protocol": "tls" if proto == "reliable" else proto,
                    "facility": _get(sl, "facility"),
                    "severity": _get(sl, "csv"),
                })

        log["syslog_servers"] = syslog_servers
        log["local_logging_enabled"] = len(sections.get("log memory setting", _FGBlock()).settings) > 0 \
            or _get(sections.get("log memory setting", _FGBlock()), "status") != "disable"

        # Forward traffic logging
        fwd_log = sections.get("log syslogd filter", _FGBlock())
        log["log_traffic"] = _get(fwd_log, "forward-traffic") == "enable"
        log["log_denied_traffic"] = _get(fwd_log, "severity") is not None

        # Check global logging setting
        gl = sections.get("log setting", _FGBlock())
        log["log_admin_actions"] = _enabled(gl, "log-user-in-upper")
        log["log_system_events"] = True  # FortiGate logs system events by default when syslog configured

        # NTP
        ntp = sections.get("system ntp", _FGBlock())
        ntp_status = _get(ntp, "status") or _get(ntp, "type")
        log["ntp_enabled"] = ntp_status not in (None, "disable")

        ntp_servers: list[str] = []
        # Nested 'config ntpserver' block (most common FortiOS style)
        ntpserver_child = ntp.children.get("ntpserver", _FGBlock())
        for _uid, entry in ntpserver_child.entries.items():
            server = _get(entry, "server")
            if server:
                ntp_servers.append(str(server))
        # Also check top-level edit entries and inline ntpserver key
        for _uid, entry in ntp.entries.items():
            server = _get(entry, "server")
            if server:
                ntp_servers.append(str(server))
        ntpsrv = _get(ntp, "ntpserver")
        if isinstance(ntpsrv, list):
            ntp_servers.extend(ntpsrv)
        elif ntpsrv:
            ntp_servers.append(str(ntpsrv))

        log["ntp_servers"] = list(set(ntp_servers))

    def _extract_vpn(self, sections: dict[str, _FGBlock], ir: dict) -> None:
        vpn = ir["vpn"]

        # IPsec Phase1
        phase1_section = sections.get("vpn ipsec phase1-interface", _FGBlock())
        phase2_section = sections.get("vpn ipsec phase2-interface", _FGBlock())

        tunnels: dict[str, dict] = {}

        for name, p1_entry in phase1_section.entries.items():
            enc_list = _list_val(p1_entry, "proposal")
            encryptions, hashes = self._split_proposals(enc_list)
            dh_groups = self._parse_dh_groups(_list_val(p1_entry, "dhgrp"))
            ike_version = _int_val(p1_entry, "ike-version") or 1
            # aggressive_mode is only relevant for IKEv1; IKEv2 does not have aggressive mode
            aggressive_mode = (
                ike_version == 1 and _get(p1_entry, "mode") == "aggressive"
            )

            tunnels[name] = {
                "name": name,
                "enabled": _get(p1_entry, "status") != "disable",
                "remote_gateway": _get(p1_entry, "remote-gw"),
                "phase1": {
                    "encryption": encryptions,
                    "authentication": hashes,
                    "dh_groups": dh_groups,
                    "lifetime_seconds": _int_val(p1_entry, "keylife") or 86400,
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
                "auth_method": _get(p1_entry, "authmethod") or "psk",
            }

        for _name, p2_entry in phase2_section.entries.items():
            phase1_name = _get(p2_entry, "phase1name")
            if phase1_name and phase1_name in tunnels:
                enc_list = _list_val(p2_entry, "proposal")
                encryptions, hashes = self._split_proposals(enc_list)
                dh_groups = self._parse_dh_groups(_list_val(p2_entry, "dhgrp"))
                tunnels[phase1_name]["phase2"] = {
                    "encryption": encryptions,
                    "authentication": hashes,
                    "dh_groups": dh_groups,
                    "lifetime_seconds": _int_val(p2_entry, "keylifeseconds") or 43200,
                    "pfs_enabled": _get(p2_entry, "pfs") != "disable",
                }

        vpn["ipsec_tunnels"] = list(tunnels.values())

        # SSL VPN
        ssl_settings = sections.get("vpn ssl settings", _FGBlock())
        ssl_enabled = _get(ssl_settings, "status") != "disable" and bool(ssl_settings.settings)
        vpn["ssl_vpn"]["enabled"] = ssl_enabled
        if ssl_enabled:
            tls_ver = _get(ssl_settings, "ssl-min-proto-ver") or _get(ssl_settings, "tlsv1-0")
            vpn["ssl_vpn"]["tls_versions"] = self._parse_tls_versions(str(tls_ver)) if tls_ver else []

            ciphers_raw = _get(ssl_settings, "algorithm") or []
            vpn["ssl_vpn"]["ciphers"] = _list_val(ssl_settings, "algorithm") if ciphers_raw else []
            vpn["ssl_vpn"]["split_tunneling"] = _get(ssl_settings, "split-tunneling") == "enable"
            vpn["ssl_vpn"]["client_certificate_required"] = _get(ssl_settings, "reqclientcert") == "enable"

    def _extract_firewall_policies(self, sections: dict[str, _FGBlock], ir: dict) -> None:
        fw_section = sections.get("firewall policy", _FGBlock())
        policies: list[dict] = []

        for policy_id, entry in fw_section.entries.items():
            action_raw = str(_get(entry, "action") or "deny").lower()
            action_map = {"accept": "allow", "deny": "deny", "drop": "drop", "ipsec": "allow", "ssl-vpn": "allow"}
            action = action_map.get(action_raw, "deny")

            src_addrs = _list_val(entry, "srcaddr")
            dst_addrs = _list_val(entry, "dstaddr")
            src_intf = _list_val(entry, "srcintf")
            dst_intf = _list_val(entry, "dstintf")
            services = _list_val(entry, "service")

            policies.append({
                "id": policy_id,
                "name": _get(entry, "name"),
                "enabled": _get(entry, "status") != "disable",
                "action": action,
                "source_zones": src_intf,
                "destination_zones": dst_intf,
                "source_addresses": src_addrs,
                "destination_addresses": dst_addrs,
                "services": services,
                "protocols": [],
                "source_ports": [],
                "destination_ports": [],
                "logging_enabled": _get(entry, "logtraffic") not in ("disable", None) or _get(entry, "logtraffic-start") == "enable",
                "comment": _get(entry, "comments"),
                "schedule": _get(entry, "schedule"),
                "nat_enabled": _get(entry, "nat") == "enable",
            })

        ir["firewall_policies"] = policies

    def _extract_interfaces(self, sections: dict[str, _FGBlock], ir: dict) -> None:
        iface_section = sections.get("system interface", _FGBlock())
        interfaces: list[dict] = []

        for iface_name, entry in iface_section.entries.items():
            ip_raw = _list_val(entry, "ip")
            ip_addr = ip_raw[0] if ip_raw else None
            netmask = ip_raw[1] if len(ip_raw) > 1 else None

            allowaccess = _list_val(entry, "allowaccess")

            interfaces.append({
                "name": iface_name,
                "type": _get(entry, "type"),
                "role": _get(entry, "role"),   # "wan" | "lan" | "dmz" | "undefined" | None
                "zone": _get(entry, "vdom"),
                "ip_address": ip_addr,
                "netmask": netmask,
                "enabled": _get(entry, "status") != "down",
                "management_access": allowaccess,
                "description": _get(entry, "description") or _get(entry, "alias"),
            })

        ir["interfaces"] = interfaces

    def _extract_network_objects(self, sections: dict[str, _FGBlock], ir: dict) -> None:
        addr_section = sections.get("firewall address", _FGBlock())
        addr_grp_section = sections.get("firewall addrgrp", _FGBlock())
        svc_section = sections.get("firewall service custom", _FGBlock())
        svc_grp_section = sections.get("firewall service group", _FGBlock())

        address_objects: list[dict] = []
        for name, entry in addr_section.entries.items():
            obj_type = _get(entry, "type") or "host"
            fgtype_map = {"ipmask": "network", "iprange": "range", "fqdn": "fqdn", "wildcard-fqdn": "fqdn", "geography": "network"}
            norm_type = fgtype_map.get(str(obj_type).lower(), "host")
            subnet = _list_val(entry, "subnet")
            value = "/".join(subnet) if subnet else _get(entry, "fqdn") or _get(entry, "start-ip")
            address_objects.append({
                "name": name,
                "type": norm_type,
                "value": str(value) if value else None,
            })

        for name, entry in addr_grp_section.entries.items():
            members = _list_val(entry, "member")
            address_objects.append({
                "name": name,
                "type": "group",
                "value": ",".join(members),
            })

        service_objects: list[dict] = []
        for name, entry in svc_section.entries.items():
            proto = _get(entry, "protocol") or "TCP/UDP/SCTP"
            tcp_ports = _get(entry, "tcp-portrange")
            udp_ports = _get(entry, "udp-portrange")
            port_range = str(tcp_ports or udp_ports or "")
            service_objects.append({
                "name": name,
                "protocol": str(proto).lower(),
                "port_range": port_range,
            })

        ir["network_objects"]["address_objects"] = address_objects
        ir["network_objects"]["service_objects"] = service_objects

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _split_proposals(self, proposals: list[str]) -> tuple[list[str], list[str]]:
        """Split FortiGate proposal strings like 'aes256-sha256' into enc/hash lists."""
        encryptions: set[str] = set()
        hashes: set[str] = set()
        hash_algos = {"sha1", "sha256", "sha384", "sha512", "md5"}
        for proposal in proposals:
            parts = proposal.lower().split("-")
            # Hashes are typically suffix
            found_hash = False
            for part in reversed(parts):
                if part in hash_algos:
                    hashes.add(part)
                    found_hash = True
                    break
            enc_parts = parts[:-1] if found_hash else parts
            if enc_parts:
                encryptions.add("-".join(enc_parts))
        return sorted(encryptions), sorted(hashes)

    def _parse_dh_groups(self, groups: list[str]) -> list[int]:
        result: list[int] = []
        for g in groups:
            try:
                result.append(int(g))
            except (ValueError, TypeError):
                pass
        return result

    def _parse_tls_versions(self, raw: str) -> list[str]:
        raw = raw.lower()
        versions: list[str] = []
        mapping = {
            "tlsv1-0": "TLSv1.0",
            "tlsv1.0": "TLSv1.0",
            "tlsv1-1": "TLSv1.1",
            "tlsv1.1": "TLSv1.1",
            "tlsv1-2": "TLSv1.2",
            "tlsv1.2": "TLSv1.2",
            "tlsv1-3": "TLSv1.3",
            "tlsv1.3": "TLSv1.3",
            "tls1.0": "TLSv1.0",
            "tls1.1": "TLSv1.1",
            "tls1.2": "TLSv1.2",
            "tls1.3": "TLSv1.3",
        }
        for k, v in mapping.items():
            if k in raw:
                versions.append(v)
        # If only a minimum is specified, include all higher versions
        if "tlsv1-2" in raw or "tlsv1.2" in raw or "tls1.2" in raw:
            if "TLSv1.3" not in versions:
                versions.append("TLSv1.3")
            versions = [v for v in versions if v not in ("TLSv1.0", "TLSv1.1")]
        return sorted(set(versions)) if versions else ["TLSv1.2", "TLSv1.3"]
