"""Check Point Gaia OS configuration parser.

Parses 'show configuration' (clish format) output from Check Point Gaia OS
into the normalized FireAudit IR.

Check Point Gaia clish config is a line-oriented format using 'set' and 'add'
commands:

  set hostname FW-CP-GW
  set interface eth0 ipv4-address 203.0.113.1 mask-length 24
  set interface eth0 state on
  set ntp active on
  set ntp server primary 10.0.0.10 version 2
  add syslog log-remote-address 10.0.0.100 protocol udp port 514
  set snmp agent on
  set snmp agent-version v3

Note: Firewall policy rules are stored in the Check Point policy database,
not in the Gaia clish config. This parser handles the OS-level configuration
only; firewall_policies will be empty.
"""

from __future__ import annotations

import re
import shlex
from typing import Any

from fireaudit.parsers.base import BaseParser, infer_interface_role


# ---------------------------------------------------------------------------
# TLS version mapping
# ---------------------------------------------------------------------------

# Check Point 'set web min-ssl-version' token → normalized TLS version string
_CP_TLS_MAP: dict[str, str] = {
    "sslv3":  "TLSv1.0",   # SSLv3 is treated as effectively TLSv1.0 floor
    "tls10":  "TLSv1.0",
    "tls1":   "TLSv1.0",
    "tlsv1":  "TLSv1.0",
    "tls11":  "TLSv1.1",
    "tlsv11": "TLSv1.1",
    "tls12":  "TLSv1.2",
    "tlsv12": "TLSv1.2",
    "tls13":  "TLSv1.3",
    "tlsv13": "TLSv1.3",
}

# All TLS versions in ascending order used to derive supported-from-minimum sets
_TLS_ORDER = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]


def _tls_from_minimum(min_ver: str) -> list[str]:
    """Return all TLS versions >= min_ver."""
    try:
        idx = _TLS_ORDER.index(min_ver)
        return _TLS_ORDER[idx:]
    except ValueError:
        return ["TLSv1.2", "TLSv1.3"]


# ---------------------------------------------------------------------------
# Line tokenizer
# ---------------------------------------------------------------------------

def _tokenize_line(line: str) -> list[str]:
    """Split a clish config line into tokens, preserving quoted strings."""
    try:
        tokens = shlex.split(line)
    except ValueError:
        # Fall back to naive split on shlex error (unmatched quotes etc.)
        tokens = line.split()
    return tokens


# ---------------------------------------------------------------------------
# Main parser class
# ---------------------------------------------------------------------------

class CheckPointParser(BaseParser):
    """Parser for Check Point Gaia OS 'show configuration' (clish) output."""

    vendor = "checkpoint"

    def parse(self, content: str) -> dict:
        """Parse Gaia clish configuration text into a normalized IR dict."""
        ir = self._base_ir()

        # Parse all lines into structured records for multi-pass extraction
        lines = self._parse_lines(content)

        self._extract_meta(lines, ir)
        self._extract_admin_access(lines, ir)
        self._extract_authentication(lines, ir)
        self._extract_logging(lines, ir)
        self._extract_interfaces(lines, ir)
        # VPN and firewall policies are in the policy database — leave empty

        return ir

    # ------------------------------------------------------------------
    # Low-level line parsing
    # ------------------------------------------------------------------

    def _parse_lines(self, content: str) -> list[list[str]]:
        """Return tokenized non-comment, non-empty lines."""
        result: list[list[str]] = []
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            tokens = _tokenize_line(line)
            if tokens:
                result.append(tokens)
        return result

    def _find_lines(self, lines: list[list[str]], *prefixes: str) -> list[list[str]]:
        """Return all token lists whose leading tokens match the given prefixes."""
        depth = len(prefixes)
        result: list[list[str]] = []
        for toks in lines:
            if len(toks) >= depth and all(
                toks[i].lower() == prefixes[i].lower() for i in range(depth)
            ):
                result.append(toks)
        return result

    def _get_value(self, lines: list[list[str]], *prefixes: str) -> str | None:
        """Return the token immediately after the matching prefix sequence, or None."""
        matched = self._find_lines(lines, *prefixes)
        if not matched:
            return None
        toks = matched[0]
        rest = toks[len(prefixes):]
        return rest[0] if rest else None

    def _get_rest(self, lines: list[list[str]], *prefixes: str) -> list[str] | None:
        """Return all tokens after the matching prefix sequence, or None."""
        matched = self._find_lines(lines, *prefixes)
        if not matched:
            return None
        toks = matched[0]
        return toks[len(prefixes):]

    def _is_on(self, lines: list[list[str]], *prefixes: str) -> bool | None:
        """Return True/False/None based on the on/off/enable/disable value."""
        val = self._get_value(lines, *prefixes)
        if val is None:
            return None
        return val.lower() in ("on", "enable", "enabled", "yes", "true")

    # ------------------------------------------------------------------
    # Section extractors
    # ------------------------------------------------------------------

    def _extract_meta(self, lines: list[list[str]], ir: dict) -> None:
        ir["meta"]["hostname"] = self._get_value(lines, "set", "hostname")

        fw_ver = (
            self._get_value(lines, "set", "gaia-version")
            or self._get_value(lines, "set", "os-version")
        )
        if fw_ver:
            ir["meta"]["firmware_version"] = fw_ver

    def _extract_admin_access(self, lines: list[list[str]], ir: dict) -> None:
        aa = ir["admin_access"]
        protocols: list[dict] = []

        # --- SSH ---
        ssh_on = self._is_on(lines, "set", "ssh", "enable")
        if ssh_on is None:
            # Check alternate form: set ssh on
            ssh_on = self._is_on(lines, "set", "ssh")
        ssh_enabled = bool(ssh_on)
        protocols.append({
            "protocol": "ssh",
            "enabled": ssh_enabled,
            "port": 22,
            "interfaces": [],
            "version": "2",
        })
        aa["ssh_settings"]["enabled"] = ssh_enabled
        aa["ssh_settings"]["version"] = 2  # Check Point uses SSH v2 by default

        # --- Telnet ---
        telnet_val = self._get_value(lines, "set", "telnet")
        telnet_enabled = telnet_val is not None and telnet_val.lower() in ("on", "enable", "enabled", "yes")
        protocols.append({
            "protocol": "telnet",
            "enabled": telnet_enabled,
            "port": 23,
            "interfaces": [],
            "version": None,
        })

        # --- HTTPS / Web management ---
        web_enable_val = self._get_value(lines, "set", "web", "enable")
        # Alternate: 'set web on'
        if web_enable_val is None:
            web_enable_val = self._get_value(lines, "set", "web")
        https_enabled = web_enable_val is not None and web_enable_val.lower() in ("on", "enable", "enabled", "yes")

        web_port_val = self._get_value(lines, "set", "web", "ssl-port")
        web_port = int(web_port_val) if web_port_val and web_port_val.isdigit() else 443

        protocols.append({
            "protocol": "https",
            "enabled": https_enabled,
            "port": web_port,
            "interfaces": [],
            "version": None,
        })
        aa["https_settings"]["enabled"] = https_enabled

        # TLS version
        tls_raw = self._get_value(lines, "set", "web", "min-ssl-version")
        if tls_raw:
            min_tls = _CP_TLS_MAP.get(tls_raw.lower(), "TLSv1.2")
            aa["https_settings"]["tls_versions"] = _tls_from_minimum(min_tls)

        aa["management_protocols"] = protocols

        # --- Session timeout ---
        # 'set session-timeout <minutes>' or 'set inactivity-timeout <seconds>'
        sess_timeout = self._get_value(lines, "set", "session-timeout")
        if sess_timeout and sess_timeout.isdigit():
            aa["session_timeout_seconds"] = int(sess_timeout) * 60
        else:
            inact = self._get_value(lines, "set", "inactivity-timeout")
            if inact and inact.isdigit():
                aa["session_timeout_seconds"] = int(inact)

        # --- Banner ---
        banner = (
            self._get_value(lines, "set", "banner")
            or self._get_value(lines, "set", "motd")
        )
        aa["banner"] = banner
        aa["banner_enabled"] = banner is not None and banner.lower() not in ("", "off", "disable", "none")

        # --- Max login attempts ---
        max_auth = self._get_value(lines, "set", "login-max-failed-auth")
        if max_auth and max_auth.isdigit():
            aa["max_login_attempts"] = int(max_auth)

        # --- SNMP ---
        snmp_agent_on = self._is_on(lines, "set", "snmp", "agent")
        aa["snmp"]["enabled"] = bool(snmp_agent_on)

        snmp_ver = self._get_value(lines, "set", "snmp", "agent-version")
        if snmp_ver:
            aa["snmp"]["version"] = snmp_ver.lower()

        # Community strings: 'set snmp community <name> read-only' or 'add snmp community <name>'
        communities: list[str] = []
        for toks in self._find_lines(lines, "set", "snmp", "community"):
            if len(toks) >= 4:
                communities.append(toks[3])
        for toks in self._find_lines(lines, "add", "snmp", "community"):
            if len(toks) >= 4:
                communities.append(toks[3])
        if communities:
            aa["snmp"]["community_strings"] = list(set(communities))

        # SNMPv3 security level: 'set snmp usm user <name> security-level <level>'
        for toks in self._find_lines(lines, "set", "snmp", "usm", "user"):
            # toks: set snmp usm user <name> security-level <level>
            try:
                sl_idx = toks.index("security-level")
                level_raw = toks[sl_idx + 1].lower()
                level_map = {
                    "authpriv": "auth-priv",
                    "authnopriv": "auth-no-priv",
                    "noauthnopriv": "no-auth-no-priv",
                    "auth-priv": "auth-priv",
                    "auth-no-priv": "auth-no-priv",
                    "no-auth-no-priv": "no-auth-no-priv",
                }
                aa["snmp"]["security_level"] = level_map.get(level_raw, level_raw)
            except (ValueError, IndexError):
                pass

    def _extract_authentication(self, lines: list[list[str]], ir: dict) -> None:
        auth = ir["authentication"]

        # Local users: collect all 'set user <name> ...' lines
        users_seen: dict[str, dict] = {}
        for toks in self._find_lines(lines, "set", "user"):
            if len(toks) < 3:
                continue
            username = toks[2]
            if username not in users_seen:
                users_seen[username] = {
                    "username": username,
                    "privilege_level": None,
                    "mfa_enabled": False,
                    "password_hash_algorithm": None,
                    "account_enabled": True,
                }
            entry = users_seen[username]

            # Detect password-hash field
            if len(toks) >= 5 and toks[3].lower() == "password-hash":
                pw_hash = toks[4]
                if pw_hash.startswith("$1$"):
                    entry["password_hash_algorithm"] = "md5"
                elif pw_hash.startswith("$5$"):
                    entry["password_hash_algorithm"] = "sha256"
                elif pw_hash.startswith("$6$"):
                    entry["password_hash_algorithm"] = "sha512"

            # Shell hint → privilege
            if len(toks) >= 5 and toks[3].lower() == "shell":
                shell = toks[4]
                if shell in ("/bin/bash", "/bin/sh"):
                    entry["privilege_level"] = "admin"

        auth["local_users"] = list(users_seen.values())

        default_admin = "admin" in users_seen
        auth["default_admin_account_exists"] = default_admin
        auth["default_admin_renamed"] = not default_admin

        # Password policy
        pp = auth["password_policy"]

        min_len = self._get_value(lines, "set", "password-policy", "min-password-length")
        if min_len and min_len.isdigit():
            pp["min_length"] = int(min_len)

        max_age = self._get_value(lines, "set", "password-policy", "max-password-validity")
        if max_age and max_age.isdigit():
            pp["max_age_days"] = int(max_age)

        history = self._get_value(lines, "set", "password-policy", "history-length")
        if history and history.isdigit():
            pp["history_count"] = int(history)

        complexity = self._get_value(lines, "set", "password-policy", "complexity-class")
        if complexity is not None:
            # complexity-class 0=none, 1=low, 2=medium, 3=high (require mixed)
            try:
                cval = int(complexity)
                pp["require_uppercase"] = cval >= 2
                pp["require_lowercase"] = cval >= 2
                pp["require_numbers"] = cval >= 2
                pp["require_special"] = cval >= 3
            except ValueError:
                pass

    def _extract_logging(self, lines: list[list[str]], ir: dict) -> None:
        log = ir["logging"]

        # Local syslog: 'set syslog on'
        local_sl = self._is_on(lines, "set", "syslog")
        log["local_logging_enabled"] = bool(local_sl)

        # Remote syslog: 'add syslog log-remote-address <ip> protocol <proto> port <port>'
        syslog_servers: list[dict] = []
        for toks in self._find_lines(lines, "add", "syslog", "log-remote-address"):
            # toks: add syslog log-remote-address <ip> [protocol <proto>] [port <port>]
            if len(toks) < 4:
                continue
            host = toks[3]
            proto = "udp"
            port = 514
            try:
                if "protocol" in toks:
                    pi = toks.index("protocol")
                    proto = toks[pi + 1]
                if "port" in toks:
                    pti = toks.index("port")
                    port = int(toks[pti + 1])
            except (ValueError, IndexError):
                pass
            syslog_servers.append({"host": host, "port": port, "protocol": proto, "facility": None, "severity": None})

        log["syslog_servers"] = syslog_servers

        # NTP
        ntp_on = self._is_on(lines, "set", "ntp", "active")
        log["ntp_enabled"] = bool(ntp_on)

        ntp_servers: list[str] = []
        for role in ("primary", "secondary"):
            srv = self._get_value(lines, "set", "ntp", "server", role)
            if srv:
                ntp_servers.append(srv)
        log["ntp_servers"] = ntp_servers

    def _extract_interfaces(self, lines: list[list[str]], ir: dict) -> None:
        # Collect interface data: 'set interface <name> ...'
        ifaces: dict[str, dict] = {}

        for toks in self._find_lines(lines, "set", "interface"):
            if len(toks) < 4:
                continue
            name = toks[2]
            if name not in ifaces:
                ifaces[name] = {
                    "name": name,
                    "type": None,
                    "role": None,
                    "zone": None,
                    "ip_address": None,
                    "netmask": None,
                    "enabled": None,
                    "management_access": [],
                    "description": None,
                }
            entry = ifaces[name]
            attr = toks[3].lower()

            if attr == "ipv4-address" and len(toks) >= 5:
                entry["ip_address"] = toks[4]
                # mask-length follows: set interface <name> ipv4-address <ip> mask-length <cidr>
                try:
                    ml_idx = toks.index("mask-length")
                    entry["netmask"] = f"/{toks[ml_idx + 1]}"
                except (ValueError, IndexError):
                    pass

            elif attr == "state":
                state_val = toks[4].lower() if len(toks) >= 5 else "off"
                entry["enabled"] = state_val in ("on", "up", "enable", "enabled")

            elif attr == "comments" and len(toks) >= 5:
                entry["description"] = toks[4]

        # Infer interface roles
        for iface in ifaces.values():
            iface["role"] = infer_interface_role(iface["description"], iface["name"])

        ir["interfaces"] = list(ifaces.values())
