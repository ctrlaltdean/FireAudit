"""Juniper SRX (JunOS) configuration parser.

Parses JunOS hierarchical text format ('show configuration' output) from
Juniper SRX devices into the normalized FireAudit IR.

JunOS hierarchical config uses braces to delimit blocks:

  system {
      host-name SRX-01;
      services {
          ssh {
              protocol-version v2;
          }
          telnet;
      }
  }
  interfaces {
      ge-0/0/0 {
          description "WAN";
          unit 0 {
              family inet {
                  address 203.0.113.1/24;
              }
          }
      }
  }
  security {
      policies { ... }
      ike { ... }
      ipsec { ... }
  }

This parser builds a nested dict representation of the config, then extracts
the IR fields from it. Repeated keys at the same level become lists.
"""

from __future__ import annotations

import re
import shlex
from typing import Any

from fireaudit.parsers.base import BaseParser, infer_interface_role


# ---------------------------------------------------------------------------
# JunOS hierarchical config tokenizer and parser
# ---------------------------------------------------------------------------

def _junos_tokenize(content: str) -> list[str]:
    """Tokenize JunOS hierarchical config into meaningful tokens.

    Handles:
    - Comment lines starting with '#' or '##'
    - Quoted strings (preserved without quotes)
    - Semicolons and braces as separate tokens
    - Inline comments after /* ... */
    """
    tokens: list[str] = []
    # Strip block comments /* ... */
    content = re.sub(r"/\*.*?\*/", " ", content, flags=re.DOTALL)

    for raw_line in content.splitlines():
        line = raw_line.strip()
        # Skip comment-only lines
        if not line or line.startswith("#") or line.startswith("/*"):
            continue
        # Inline '#' comment — strip from line
        if "#" in line:
            line = line[:line.index("#")].strip()
            if not line:
                continue

        # Tokenize using shlex for quote handling, then split braces/semicolons
        try:
            raw_tokens = shlex.split(line, posix=True)
        except ValueError:
            raw_tokens = line.split()

        for tok in raw_tokens:
            # Split braces and semicolons away from adjacent text
            expanded = _expand_token(tok)
            tokens.extend(expanded)

    return tokens


def _expand_token(tok: str) -> list[str]:
    """Split a token on { } ; boundaries, emitting each as its own token."""
    result: list[str] = []
    current = ""
    for ch in tok:
        if ch in ("{", "}", ";"):
            if current:
                result.append(current)
                current = ""
            result.append(ch)
        else:
            current += ch
    if current:
        result.append(current)
    return result


def _parse_junos_block(tokens: list[str], pos: int) -> tuple[dict, int]:
    """Recursively parse a JunOS config block (already inside braces).

    Returns (dict_of_contents, new_pos).  Pos should be just after the
    opening '{'.  Stops at the matching '}'.

    Rules:
    - 'key;'            → {key: None}
    - 'key value;'      → {key: value}
    - 'key { ... }'     → {key: {recursive}}
    - Repeated key      → value becomes list

    When a key maps to both a scalar and a sub-block (e.g. 'server 1.2.3.4 { ... }'),
    the sub-block takes precedence but we also record the value as a special
    '_value' key inside the child dict.
    """
    result: dict[str, Any] = {}

    def _set(d: dict, key: str, value: Any) -> None:
        """Insert key/value into d, converting to list on collision."""
        if key not in d:
            d[key] = value
        else:
            existing = d[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                d[key] = [existing, value]

    while pos < len(tokens):
        tok = tokens[pos]

        if tok == "}":
            pos += 1
            break

        if tok == ";":
            pos += 1
            continue

        # tok is a key (or an orphan ';' already handled above)
        key = tok
        pos += 1

        # Collect value tokens until ';', '{', or '}' or end
        value_parts: list[str] = []
        while pos < len(tokens) and tokens[pos] not in (";", "{", "}"):
            value_parts.append(tokens[pos])
            pos += 1

        if pos < len(tokens) and tokens[pos] == ";":
            # Simple scalar: key [value ...] ;
            pos += 1
            value = " ".join(value_parts) if value_parts else None
            _set(result, key, value)

        elif pos < len(tokens) and tokens[pos] == "{":
            # Block: key [value-prefix] { ... }
            pos += 1  # consume '{'
            child, pos = _parse_junos_block(tokens, pos)
            # If there were value tokens before '{', treat them as the block key qualifier
            # e.g. 'community public { ... }' → key='community', sub-key='public'
            if value_parts:
                # Wrap child under the value-parts key chain
                sub_key = " ".join(value_parts)
                # Build nested dict for multi-word sub-keys
                sub_parts = value_parts
                if len(sub_parts) == 1:
                    child_wrapper: dict = {sub_parts[0]: child}
                else:
                    # Multiple words → nested
                    inner: dict = child
                    for sp in reversed(sub_parts[1:]):
                        inner = {sp: inner}
                    child_wrapper = {sub_parts[0]: inner}
                # Merge child_wrapper into result under key
                if key not in result:
                    result[key] = child_wrapper
                else:
                    existing = result[key]
                    if isinstance(existing, dict):
                        # Merge child_wrapper into existing
                        for ck, cv in child_wrapper.items():
                            _set(existing, ck, cv)
                    elif isinstance(existing, list):
                        # Append the new wrapper dict, then try to merge
                        existing.append(child_wrapper)
                    else:
                        result[key] = [existing, child_wrapper]
            else:
                _set(result, key, child)

        elif pos < len(tokens) and tokens[pos] == "}":
            # Key with value parts but no terminating semicolon before '}'
            value = " ".join(value_parts) if value_parts else None
            _set(result, key, value)
            # Don't consume '}' — let outer loop handle it

        else:
            # End of tokens
            value = " ".join(value_parts) if value_parts else None
            _set(result, key, value)

    return result, pos


def _parse_junos_config(content: str) -> dict:
    """Parse a complete JunOS hierarchical config into a nested dict."""
    tokens = _junos_tokenize(content)
    root: dict[str, Any] = {}
    pos = 0
    # Extract version line before block parsing
    # 'version X.Y;' at the top level
    ver_match = re.search(r"^version\s+(\S+)\s*;", content, re.MULTILINE)
    if ver_match:
        root["version"] = ver_match.group(1)

    while pos < len(tokens):
        tok = tokens[pos]
        if tok in (";", "}"):
            pos += 1
            continue

        key = tok
        pos += 1

        value_parts: list[str] = []
        while pos < len(tokens) and tokens[pos] not in (";", "{", "}"):
            value_parts.append(tokens[pos])
            pos += 1

        if pos < len(tokens) and tokens[pos] == ";":
            pos += 1
            value = " ".join(value_parts) if value_parts else None
            if key not in root:
                root[key] = value
        elif pos < len(tokens) and tokens[pos] == "{":
            pos += 1
            child, pos = _parse_junos_block(tokens, pos)
            if value_parts:
                sub_key = " ".join(value_parts)
                if sub_key:
                    child_wrapped = {sub_key: child}
                    if key not in root:
                        root[key] = child_wrapped
                    elif isinstance(root[key], dict):
                        for ck, cv in child_wrapped.items():
                            existing = root[key]
                            if ck not in existing:
                                existing[ck] = cv
                            else:
                                ev = existing[ck]
                                if isinstance(ev, list):
                                    ev.append(cv)
                                else:
                                    existing[ck] = [ev, cv]
                    else:
                        root[key] = child_wrapped
                else:
                    root[key] = child
            else:
                root[key] = child
        else:
            value = " ".join(value_parts) if value_parts else None
            root[key] = value

    return root


# ---------------------------------------------------------------------------
# Safe nested-dict accessor helpers
# ---------------------------------------------------------------------------

def _dig(d: Any, *keys: str) -> Any:
    """Safely navigate a nested dict chain. Returns None if any key is missing."""
    current = d
    for k in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(k)
    return current


def _dig_list(d: Any, *keys: str) -> list:
    """Like _dig but always returns a list (wraps scalar in list if needed)."""
    val = _dig(d, *keys)
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]


def _str_val(d: Any, *keys: str) -> str | None:
    """Return string value at path, or None."""
    val = _dig(d, *keys)
    if val is None or isinstance(val, dict):
        return None
    return str(val)


def _int_val(d: Any, *keys: str) -> int | None:
    """Return int value at path, or None."""
    val = _str_val(d, *keys)
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Main parser class
# ---------------------------------------------------------------------------

class JuniperSRXParser(BaseParser):
    """Parser for Juniper SRX JunOS hierarchical configuration files."""

    vendor = "juniper_srx"

    def parse(self, content: str) -> dict:
        """Parse JunOS hierarchical configuration into a normalized IR dict."""
        cfg = _parse_junos_config(content)
        ir = self._base_ir()

        self._extract_meta(cfg, ir)
        self._extract_admin_access(cfg, ir)
        self._extract_authentication(cfg, ir)
        self._extract_logging(cfg, ir)
        self._extract_interfaces(cfg, ir)
        self._extract_vpn(cfg, ir)
        self._extract_firewall_policies(cfg, ir)

        return ir

    # ------------------------------------------------------------------
    # Section extractors
    # ------------------------------------------------------------------

    def _extract_meta(self, cfg: dict, ir: dict) -> None:
        ir["meta"]["hostname"] = _str_val(cfg, "system", "host-name")
        ir["meta"]["firmware_version"] = _str_val(cfg, "version")

    def _extract_admin_access(self, cfg: dict, ir: dict) -> None:
        aa = ir["admin_access"]
        system = cfg.get("system", {}) or {}
        services = _dig(system, "services") or {}
        protocols: list[dict] = []

        # --- SSH ---
        ssh_block = _dig(services, "ssh")
        ssh_enabled = isinstance(ssh_block, dict) or ssh_block is not None
        ssh_ver_raw = _str_val(services, "ssh", "protocol-version") if isinstance(ssh_block, dict) else None
        ssh_version = 2
        if ssh_ver_raw:
            m = re.search(r"(\d+)", ssh_ver_raw)
            ssh_version = int(m.group(1)) if m else 2

        protocols.append({
            "protocol": "ssh",
            "enabled": ssh_enabled,
            "port": 22,
            "interfaces": [],
            "version": str(ssh_version),
        })
        aa["ssh_settings"]["enabled"] = ssh_enabled
        aa["ssh_settings"]["version"] = ssh_version

        # SSH idle timeout
        ssh_idle = _int_val(services, "ssh", "client-alive-interval")
        if ssh_idle:
            aa["session_timeout_seconds"] = ssh_idle

        # --- Telnet ---
        telnet_val = _dig(services, "telnet")
        telnet_enabled = telnet_val is not None
        protocols.append({
            "protocol": "telnet",
            "enabled": telnet_enabled,
            "port": 23,
            "interfaces": [],
            "version": None,
        })

        # --- HTTPS / web-management ---
        web_mgmt = _dig(services, "web-management")
        https_block = _dig(services, "web-management", "https") if isinstance(web_mgmt, dict) else None
        https_enabled = isinstance(https_block, dict) or https_block is not None

        https_port_raw = _str_val(services, "web-management", "https", "port") if isinstance(https_block, dict) else None
        https_port = int(https_port_raw) if https_port_raw and https_port_raw.isdigit() else 443

        protocols.append({
            "protocol": "https",
            "enabled": https_enabled,
            "port": https_port,
            "interfaces": [],
            "version": None,
        })
        aa["https_settings"]["enabled"] = https_enabled

        aa["management_protocols"] = protocols

        # --- Banner ---
        banner = _str_val(system, "login", "message")
        aa["banner"] = banner
        aa["banner_enabled"] = banner is not None and banner.strip() not in ("", "none")

        # --- Max login attempts ---
        max_tries = _int_val(system, "login", "retry-options", "tries-before-disconnect")
        if max_tries is not None:
            aa["max_login_attempts"] = max_tries

        # --- SNMP ---
        snmp_block = _dig(system, "snmp")
        snmp_enabled = snmp_block is not None and snmp_block != {}
        aa["snmp"]["enabled"] = bool(snmp_enabled)

        if isinstance(snmp_block, dict):
            # Community strings from 'community <name> { authorization read-only; }'
            community_data = snmp_block.get("community")
            communities: list[str] = []
            if isinstance(community_data, dict):
                # Single community named by key
                for cname in community_data:
                    if not cname.startswith("_"):
                        communities.append(cname)
            elif isinstance(community_data, list):
                for item in community_data:
                    if isinstance(item, dict):
                        for cname in item:
                            if not cname.startswith("_"):
                                communities.append(cname)
                    elif isinstance(item, str):
                        communities.append(item)
            if communities:
                aa["snmp"]["community_strings"] = communities
                aa["snmp"]["version"] = "v2c"

            # SNMPv3 configuration
            v3_block = _dig(snmp_block, "v3")
            if v3_block is not None:
                aa["snmp"]["version"] = "v3"
                # Determine security level from USM user block
                # Look for authentication-sha/md5 and privacy-aes128/des presence
                usm_users = _dig(v3_block, "usm", "local-engine", "user")
                if isinstance(usm_users, dict):
                    has_auth = any(
                        k in usm_users for k in ("authentication-sha", "authentication-md5",
                                                   "authentication-sha256", "authentication-sha384")
                    )
                    has_priv = any(
                        k in usm_users for k in ("privacy-aes128", "privacy-des",
                                                   "privacy-3des", "privacy-aes192", "privacy-aes256")
                    )
                    if has_auth and has_priv:
                        aa["snmp"]["security_level"] = "auth-priv"
                    elif has_auth:
                        aa["snmp"]["security_level"] = "auth-no-priv"
                    else:
                        aa["snmp"]["security_level"] = "no-auth-no-priv"

    def _extract_authentication(self, cfg: dict, ir: dict) -> None:
        auth = ir["authentication"]
        system = cfg.get("system", {}) or {}
        login_block = _dig(system, "login") or {}

        # Local users
        users: list[dict] = []
        default_admin_exists = False

        # Root authentication is a special case
        root_auth = _dig(system, "root-authentication")
        if root_auth is not None:
            default_admin_exists = True
            root_hash = None
            if isinstance(root_auth, dict):
                enc_pw = _str_val(root_auth, "encrypted-password")
                if enc_pw:
                    if enc_pw.startswith("$1$"):
                        root_hash = "md5"
                    elif enc_pw.startswith("$5$"):
                        root_hash = "sha256"
                    elif enc_pw.startswith("$6$"):
                        root_hash = "sha512"
            users.append({
                "username": "root",
                "privilege_level": "super_admin",
                "mfa_enabled": False,
                "password_hash_algorithm": root_hash,
                "account_enabled": True,
            })

        # Named users under 'login { user <name> { ... } }'
        if isinstance(login_block, dict):
            user_data = login_block.get("user")
            user_items: dict = {}
            if isinstance(user_data, dict):
                # Could be {username: {block}} or just one level
                for uname, ublock in user_data.items():
                    if uname.startswith("_"):
                        continue
                    if isinstance(ublock, dict):
                        user_items[uname] = ublock
                    else:
                        user_items[uname] = {}
            elif isinstance(user_data, list):
                for item in user_data:
                    if isinstance(item, dict):
                        for uname, ublock in item.items():
                            if isinstance(ublock, dict):
                                user_items[uname] = ublock

            for uname, ublock in user_items.items():
                if uname.lower() == "admin":
                    default_admin_exists = True

                cls = _str_val(ublock, "class") if isinstance(ublock, dict) else None
                priv = "super_admin" if cls in ("super-user", "superuser") else cls

                enc_pw = None
                if isinstance(ublock, dict):
                    auth_block = ublock.get("authentication")
                    if isinstance(auth_block, dict):
                        enc_pw = _str_val(auth_block, "encrypted-password")

                hash_algo = None
                if enc_pw:
                    if enc_pw.startswith("$1$"):
                        hash_algo = "md5"
                    elif enc_pw.startswith("$5$"):
                        hash_algo = "sha256"
                    elif enc_pw.startswith("$6$"):
                        hash_algo = "sha512"

                users.append({
                    "username": uname,
                    "privilege_level": priv,
                    "mfa_enabled": False,
                    "password_hash_algorithm": hash_algo,
                    "account_enabled": True,
                })

        auth["local_users"] = users
        auth["default_admin_account_exists"] = default_admin_exists
        auth["default_admin_renamed"] = not default_admin_exists

        # Password policy from 'system login password { ... }'
        pw_block = _dig(login_block, "password") if isinstance(login_block, dict) else None
        if isinstance(pw_block, dict):
            pp = auth["password_policy"]
            min_len = _int_val(pw_block, "minimum-length")
            if min_len:
                pp["min_length"] = min_len
            max_age = _int_val(pw_block, "maximum-password-lifetime")
            if max_age:
                pp["max_age_days"] = max_age
            min_changes = _int_val(pw_block, "minimum-changes")
            if min_changes:
                pp["history_count"] = min_changes

    def _extract_logging(self, cfg: dict, ir: dict) -> None:
        log = ir["logging"]
        system = cfg.get("system", {}) or {}

        # Syslog
        syslog_block = _dig(system, "syslog") or {}
        syslog_servers: list[dict] = []

        if isinstance(syslog_block, dict):
            host_data = syslog_block.get("host")
            if isinstance(host_data, dict):
                for host_ip, host_cfg in host_data.items():
                    if host_ip.startswith("_"):
                        continue
                    port = 514
                    if isinstance(host_cfg, dict):
                        port_val = _str_val(host_cfg, "port")
                        if port_val and port_val.isdigit():
                            port = int(port_val)
                    syslog_servers.append({
                        "host": host_ip,
                        "port": port,
                        "protocol": "udp",
                        "facility": None,
                        "severity": None,
                    })
            elif isinstance(host_data, list):
                for item in host_data:
                    if isinstance(item, dict):
                        for host_ip, host_cfg in item.items():
                            port = 514
                            if isinstance(host_cfg, dict):
                                port_val = _str_val(host_cfg, "port")
                                if port_val and port_val.isdigit():
                                    port = int(port_val)
                            syslog_servers.append({
                                "host": host_ip,
                                "port": port,
                                "protocol": "udp",
                                "facility": None,
                                "severity": None,
                            })

            # Local file logging → local_logging_enabled
            file_block = syslog_block.get("file")
            log["local_logging_enabled"] = file_block is not None

        log["syslog_servers"] = syslog_servers

        # NTP
        ntp_block = _dig(system, "ntp") or {}
        ntp_servers: list[str] = []

        if isinstance(ntp_block, dict):
            server_val = ntp_block.get("server")
            if isinstance(server_val, str):
                ntp_servers.append(server_val.split()[0])  # strip 'prefer' suffix
            elif isinstance(server_val, list):
                for sv in server_val:
                    if isinstance(sv, str):
                        ntp_servers.append(sv.split()[0])
                    elif isinstance(sv, dict):
                        for sip in sv:
                            if not sip.startswith("_"):
                                ntp_servers.append(sip)

        log["ntp_enabled"] = len(ntp_servers) > 0
        log["ntp_servers"] = ntp_servers

    def _extract_interfaces(self, cfg: dict, ir: dict) -> None:
        ifaces_block = cfg.get("interfaces") or {}
        interfaces: list[dict] = []

        if not isinstance(ifaces_block, dict):
            ir["interfaces"] = interfaces
            return

        for iface_name, iface_data in ifaces_block.items():
            if iface_name.startswith("_") or not isinstance(iface_data, dict):
                continue

            description = _str_val(iface_data, "description")

            # IP address from unit 0 family inet address
            # Structure: iface_data.unit.0.family.inet.address
            ip_address = None
            unit_data = iface_data.get("unit")
            if isinstance(unit_data, dict):
                unit0 = unit_data.get("0") or {}
                if isinstance(unit0, dict):
                    addr_val = _str_val(unit0, "family", "inet", "address")
                    if addr_val:
                        ip_address = addr_val.split()[0]  # strip any trailing flags
            elif unit_data is None:
                # Flat structure
                addr_val = _str_val(iface_data, "family", "inet", "address")
                if addr_val:
                    ip_address = addr_val.split()[0]

            role = infer_interface_role(description, iface_name)

            interfaces.append({
                "name": iface_name,
                "type": None,
                "role": role,
                "zone": None,
                "ip_address": ip_address,
                "netmask": None,
                "enabled": True,  # JunOS interfaces are enabled by default unless 'disable;'
                "management_access": [],
                "description": description,
            })

        ir["interfaces"] = interfaces

    def _extract_vpn(self, cfg: dict, ir: dict) -> None:
        vpn = ir["vpn"]
        security = cfg.get("security") or {}
        if not isinstance(security, dict):
            return

        ike_block = _dig(security, "ike") or {}
        ipsec_block = _dig(security, "ipsec") or {}

        if not isinstance(ike_block, dict):
            return

        # Parse IKE proposals
        ike_proposals: dict[str, dict] = {}
        proposal_data = ike_block.get("proposal")
        if isinstance(proposal_data, dict):
            for prop_name, prop_cfg in proposal_data.items():
                if not isinstance(prop_cfg, dict):
                    continue
                ike_proposals[prop_name] = {
                    "encryption": _str_val(prop_cfg, "encryption-algorithm"),
                    "authentication": _str_val(prop_cfg, "authentication-algorithm"),
                    "dh_group": _str_val(prop_cfg, "dh-group"),
                    "lifetime": _int_val(prop_cfg, "lifetime-seconds"),
                    "auth_method": _str_val(prop_cfg, "authentication-method"),
                }

        # Parse IKE policies (link to proposals)
        ike_policies: dict[str, dict] = {}
        policy_data = ike_block.get("policy")
        if isinstance(policy_data, dict):
            for pol_name, pol_cfg in policy_data.items():
                if not isinstance(pol_cfg, dict):
                    continue
                ike_policies[pol_name] = {
                    "mode": _str_val(pol_cfg, "mode"),
                    "proposals": _str_val(pol_cfg, "proposals"),
                    "psk": "pre-shared-key" in pol_cfg or "ascii-text" in str(pol_cfg),
                }

        # Parse IKE gateways
        gateway_data = ike_block.get("gateway")
        if not isinstance(gateway_data, dict):
            ir["vpn"]["ipsec_tunnels"] = []
            return

        # Parse IPsec proposals
        ipsec_proposals: dict[str, dict] = {}
        if isinstance(ipsec_block, dict):
            ip_prop_data = ipsec_block.get("proposal")
            if isinstance(ip_prop_data, dict):
                for prop_name, prop_cfg in ip_prop_data.items():
                    if not isinstance(prop_cfg, dict):
                        continue
                    ipsec_proposals[prop_name] = {
                        "encryption": _str_val(prop_cfg, "encryption-algorithm"),
                        "authentication": _str_val(prop_cfg, "authentication-algorithm"),
                        "lifetime": _int_val(prop_cfg, "lifetime-seconds"),
                    }

        # Parse IPsec policies
        ipsec_policies: dict[str, dict] = {}
        if isinstance(ipsec_block, dict):
            ip_pol_data = ipsec_block.get("policy")
            if isinstance(ip_pol_data, dict):
                for pol_name, pol_cfg in ip_pol_data.items():
                    if not isinstance(pol_cfg, dict):
                        continue
                    ipsec_policies[pol_name] = {
                        "proposals": _str_val(pol_cfg, "proposals"),
                        "pfs": _dig(pol_cfg, "perfect-forward-secrecy") is not None,
                        "pfs_group": _str_val(pol_cfg, "perfect-forward-secrecy", "keys"),
                    }

        # Parse IPsec VPN tunnels
        ipsec_vpns: dict[str, dict] = {}
        if isinstance(ipsec_block, dict):
            vpn_data = ipsec_block.get("vpn")
            if isinstance(vpn_data, dict):
                for vpn_name, vpn_cfg in vpn_data.items():
                    if not isinstance(vpn_cfg, dict):
                        continue
                    ipsec_vpns[vpn_name] = {
                        "gateway": _str_val(vpn_cfg, "gateway"),
                        "ipsec_policy": _str_val(vpn_cfg, "ipsec-policy"),
                    }

        # Build tunnel IR entries per IKE gateway
        tunnels: list[dict] = []
        for gw_name, gw_cfg in gateway_data.items():
            if not isinstance(gw_cfg, dict):
                continue

            gw_address = _str_val(gw_cfg, "address")
            ike_policy_name = _str_val(gw_cfg, "ike-policy")
            ike_pol = ike_policies.get(ike_policy_name, {})
            ike_prop_name = ike_pol.get("proposals")
            ike_prop = ike_proposals.get(str(ike_prop_name), {}) if ike_prop_name else {}

            # Find associated IPsec VPN (by gateway reference)
            associated_vpn: dict = {}
            ipsec_pol: dict = {}
            ipsec_prop: dict = {}
            for vpn_name, vpn_info in ipsec_vpns.items():
                if vpn_info.get("gateway") == gw_name:
                    associated_vpn = vpn_info
                    ipsec_pol_name = vpn_info.get("ipsec_policy")
                    if ipsec_pol_name:
                        ipsec_pol = ipsec_policies.get(str(ipsec_pol_name), {})
                        ip_prop_name = ipsec_pol.get("proposals")
                        if ip_prop_name:
                            ipsec_prop = ipsec_proposals.get(str(ip_prop_name), {})
                    break

            mode = ike_pol.get("mode", "main")
            aggressive_mode = str(mode).lower() == "aggressive"

            auth_method = "psk" if ike_pol.get("psk") else "certificate"
            if ike_prop.get("auth_method"):
                raw_auth = str(ike_prop["auth_method"]).lower()
                if "pre-shared" in raw_auth or "psk" in raw_auth:
                    auth_method = "psk"
                elif "certificate" in raw_auth or "rsa" in raw_auth:
                    auth_method = "certificate"

            # Parse DH group number from string like "group14"
            dh_raw = ike_prop.get("dh_group") or ""
            dh_groups = self._parse_dh_group(str(dh_raw))

            ipsec_pfs_group_raw = ipsec_pol.get("pfs_group") or ""
            ipsec_dh = self._parse_dh_group(str(ipsec_pfs_group_raw))

            tunnels.append({
                "name": gw_name,
                "enabled": True,
                "remote_gateway": gw_address,
                "phase1": {
                    "encryption": [ike_prop.get("encryption")] if ike_prop.get("encryption") else [],
                    "authentication": [ike_prop.get("authentication")] if ike_prop.get("authentication") else [],
                    "dh_groups": dh_groups,
                    "lifetime_seconds": ike_prop.get("lifetime") or 28800,
                    "pfs_enabled": True,
                    "ike_version": 1,  # JunOS SRX uses IKEv1 by default in this block style
                    "aggressive_mode": aggressive_mode,
                },
                "phase2": {
                    "encryption": [ipsec_prop.get("encryption")] if ipsec_prop.get("encryption") else [],
                    "authentication": [ipsec_prop.get("authentication")] if ipsec_prop.get("authentication") else [],
                    "dh_groups": ipsec_dh,
                    "lifetime_seconds": ipsec_prop.get("lifetime") or 3600,
                    "pfs_enabled": ipsec_pol.get("pfs", False),
                },
                "auth_method": auth_method,
            })

        vpn["ipsec_tunnels"] = tunnels

    def _extract_firewall_policies(self, cfg: dict, ir: dict) -> None:
        security = cfg.get("security") or {}
        if not isinstance(security, dict):
            return

        policies_block = _dig(security, "policies")
        if not isinstance(policies_block, dict):
            return

        policies: list[dict] = []
        policy_id = 1

        # Structure: policies.from-zone <src> to-zone <dst>.policy.<name>
        # After parsing, this becomes nested dicts keyed on zone-pair strings
        for zone_pair_key, zone_pair_val in policies_block.items():
            # zone_pair_key may be "from-zone" with nested structure
            # due to the parser, 'from-zone trust to-zone untrust' becomes:
            # { "from-zone": { "trust": { "to-zone": { "untrust": { "policy": {...} } } } } }
            if zone_pair_key == "from-zone" and isinstance(zone_pair_val, dict):
                for src_zone, src_val in zone_pair_val.items():
                    if not isinstance(src_val, dict):
                        continue
                    to_zone_data = src_val.get("to-zone")
                    if not isinstance(to_zone_data, dict):
                        continue
                    for dst_zone, dst_val in to_zone_data.items():
                        if not isinstance(dst_val, dict):
                            continue
                        policy_data = dst_val.get("policy")
                        if not isinstance(policy_data, dict):
                            continue

                        for pol_name, pol_cfg in policy_data.items():
                            if not isinstance(pol_cfg, dict):
                                continue

                            match_block = pol_cfg.get("match") or {}
                            then_block = pol_cfg.get("then") or {}

                            if isinstance(match_block, dict):
                                src_addrs = _dig_list(match_block, "source-address")
                                dst_addrs = _dig_list(match_block, "destination-address")
                                services_val = _dig_list(match_block, "application")
                            else:
                                src_addrs = []
                                dst_addrs = []
                                services_val = []

                            # Normalize to lists of strings
                            src_addrs = [str(a) for a in (src_addrs if isinstance(src_addrs, list) else [src_addrs])]
                            dst_addrs = [str(a) for a in (dst_addrs if isinstance(dst_addrs, list) else [dst_addrs])]
                            services_val = [str(s) for s in (services_val if isinstance(services_val, list) else [services_val])]

                            action = "deny"
                            if isinstance(then_block, dict):
                                if "permit" in then_block:
                                    action = "allow"
                                elif "deny" in then_block:
                                    action = "deny"
                                elif "reject" in then_block:
                                    action = "drop"
                            elif isinstance(then_block, str):
                                if "permit" in then_block:
                                    action = "allow"

                            log_enabled = isinstance(then_block, dict) and "log" in then_block

                            policies.append({
                                "id": str(policy_id),
                                "name": pol_name,
                                "enabled": True,
                                "action": action,
                                "source_zones": [src_zone],
                                "destination_zones": [dst_zone],
                                "source_addresses": src_addrs,
                                "destination_addresses": dst_addrs,
                                "services": services_val,
                                "protocols": [],
                                "source_ports": [],
                                "destination_ports": [],
                                "logging_enabled": log_enabled,
                                "comment": None,
                                "schedule": None,
                                "nat_enabled": False,
                            })
                            policy_id += 1

        ir["firewall_policies"] = policies

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _parse_dh_group(self, raw: str) -> list[int]:
        """Extract DH group number from strings like 'group14', 'group2', 'group 14'."""
        if not raw:
            return []
        m = re.search(r"(\d+)", raw)
        if m:
            try:
                return [int(m.group(1))]
            except ValueError:
                pass
        return []
