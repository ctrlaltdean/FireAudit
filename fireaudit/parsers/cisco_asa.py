"""Cisco ASA / FTD configuration parser.

Parses 'show running-config' text output from Cisco ASA (and FTD in ASA
compatibility mode) into the FireAudit IR.

ASA config is a line-oriented format with indented sub-commands:

  hostname ASA-FW-01
  !
  interface GigabitEthernet0/0
   nameif outside
   security-level 0
   ip address 203.0.113.1 255.255.255.248
  !
  access-list OUTSIDE_IN extended permit tcp any host 10.20.1.100 eq 443
  !
  crypto ikev2 policy 10
   encryption aes-256
   integrity sha256
   group 14
  !
  username admin privilege 15 password ...
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from fireaudit.parsers.base import BaseParser, infer_interface_role


# ---------------------------------------------------------------------------
# Low-level line parser — builds an indented block tree
# ---------------------------------------------------------------------------

class _Block:
    """Represents an indented configuration block."""

    def __init__(self, header: str = "root") -> None:
        self.header = header
        self.children: list["_Block"] = []

    def lines(self) -> list[str]:
        """Return all direct non-block child lines (leaf commands)."""
        return [c.header for c in self.children if not c.children]

    def sub_blocks(self, prefix: str | None = None) -> list["_Block"]:
        """Return child blocks (blocks with children), optionally filtered by prefix."""
        result = [c for c in self.children if c.children]
        if prefix:
            result = [b for b in result if b.header.startswith(prefix)]
        return result

    def find_line(self, prefix: str) -> str | None:
        """Find first line starting with prefix."""
        for line in self.lines():
            if line.startswith(prefix):
                return line
        return None

    def find_lines(self, prefix: str) -> list[str]:
        """Find all lines starting with prefix."""
        return [l for l in self.lines() if l.startswith(prefix)]

    def find_block(self, prefix: str) -> "_Block | None":
        """Find first child block whose header starts with prefix."""
        for c in self.children:
            if c.header.startswith(prefix):
                return c
        return None

    def find_blocks(self, prefix: str) -> list["_Block"]:
        return [c for c in self.children if c.header.startswith(prefix)]

    def get_value(self, prefix: str) -> str | None:
        """Find line with prefix and return the remainder after the prefix."""
        line = self.find_line(prefix)
        if line is None:
            return None
        return line[len(prefix):].strip() or None


def _parse_blocks(content: str) -> _Block:
    """Parse ASA config into a nested block tree using indentation."""
    root = _Block("root")
    stack: list[_Block] = [root]

    for raw_line in content.splitlines():
        # Strip trailing whitespace but preserve leading for indentation
        stripped = raw_line.rstrip()
        if not stripped or stripped.startswith("!"):
            # '!' marks end of block / separator
            if stripped == "!" or not stripped:
                if len(stack) > 1:
                    stack.pop()
            continue

        # Remove leading spaces to get the command
        cmd = stripped.lstrip()
        indent = len(stripped) - len(cmd)

        # If indented, it belongs to the current block
        if indent > 0 and len(stack) > 1:
            node = _Block(cmd)
            stack[-1].children.append(node)
            # Look-ahead not needed: sub-blocks are identified by having children
        else:
            # Top-level command — add to root, pop stack back to root first
            while len(stack) > 1:
                stack.pop()
            node = _Block(cmd)
            root.children.append(node)
            stack.append(node)

    return root


# ---------------------------------------------------------------------------
# Value extraction helpers
# ---------------------------------------------------------------------------

def _val(line: str | None, prefix: str = "") -> str | None:
    """Strip prefix from line and return remainder, or None."""
    if line is None:
        return None
    line = line.strip()
    if prefix and line.startswith(prefix):
        return line[len(prefix):].strip() or None
    return line or None


def _re_val(line: str | None, pattern: str, group: int = 1) -> str | None:
    """Apply regex to line and return matched group, or None."""
    if line is None:
        return None
    m = re.search(pattern, line)
    return m.group(group) if m else None


def _ip_mask_to_cidr(ip: str, mask: str) -> str:
    """Convert 'x.x.x.x 255.255.255.0' style to 'x.x.x.x/prefix'."""
    try:
        parts = [int(b) for b in mask.split(".")]
        prefix = sum(bin(b).count("1") for b in parts)
        return f"{ip}/{prefix}"
    except (ValueError, AttributeError):
        return f"{ip} {mask}"


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

class CiscoASAParser(BaseParser):
    """Parser for Cisco ASA 'show running-config' text output."""

    vendor = "cisco_asa"

    # Weak crypto constants
    WEAK_CIPHERS = {"des", "3des", "null", "rc4"}
    WEAK_HASHES = {"md5", "sha-1", "sha1"}
    WEAK_DH = {1, 2, 5}

    def parse(self, content: str) -> dict:
        root = _parse_blocks(content)
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
    # Section extractors
    # ------------------------------------------------------------------

    def _extract_meta(self, root: _Block, ir: dict) -> None:
        hostname_line = root.find_line("hostname ")
        ir["meta"]["hostname"] = _val(hostname_line, "hostname")

        # ASA version line: "ASA Version 9.16(4)"
        for line in root.lines():
            m = re.match(r"^(?:ASA|FXOS|FTD)\s+Version\s+(\S+)", line, re.IGNORECASE)
            if m:
                ir["meta"]["firmware_version"] = m.group(1)
                break

    def _extract_admin_access(self, root: _Block, ir: dict) -> None:
        aa = ir["admin_access"]
        protocols: list[dict] = []

        # --- SSH ---
        ssh_lines = root.find_lines("ssh ")
        # 'ssh version 2' or 'ssh version 1'
        ssh_version = 2
        for line in ssh_lines:
            m = re.match(r"ssh version (\d)", line)
            if m:
                ssh_version = int(m.group(1))
        ssh_enabled = len(ssh_lines) > 0
        protocols.append({
            "protocol": "ssh",
            "enabled": ssh_enabled,
            "port": self._get_ssh_port(root),
            "interfaces": [],
            "version": str(ssh_version),
        })
        aa["ssh_settings"]["enabled"] = ssh_enabled
        aa["ssh_settings"]["version"] = ssh_version

        # --- Telnet ---
        telnet_lines = root.find_lines("telnet ")
        # 'telnet <ip> <mask> <interface>' — if any non-timeout telnet lines, it's enabled
        telnet_enabled = any(
            not l.startswith("telnet timeout") for l in telnet_lines
        )
        protocols.append({
            "protocol": "telnet",
            "enabled": telnet_enabled,
            "port": 23,
            "interfaces": [],
            "version": None,
        })

        # --- HTTPS (ASDM) ---
        http_lines = root.find_lines("http ")
        http_server_enabled = root.find_line("http server enable") is not None
        http_enabled = root.find_line("no http server enable") is None and http_server_enabled
        # Check if any http access rules defined
        https_port = None
        for line in http_lines:
            m = re.match(r"http server enable(?:\s+(\d+))?", line)
            if m:
                https_port = int(m.group(1)) if m.group(1) else 443
                http_enabled = True

        protocols.append({
            "protocol": "https",
            "enabled": http_enabled,
            "port": https_port or 443,
            "interfaces": [],
            "version": None,
        })
        aa["https_settings"]["enabled"] = http_enabled

        # TLS version
        ssl_line = root.find_line("ssl server-version ")
        if ssl_line:
            tls_raw = _val(ssl_line, "ssl server-version") or ""
            aa["https_settings"]["tls_versions"] = self._parse_tls_versions(tls_raw)

        # HTTP (plaintext) — ASA management via HTTP
        protocols.append({
            "protocol": "http",
            "enabled": False,  # ASA ASDM always uses HTTPS
            "port": 80,
            "interfaces": [],
            "version": None,
        })

        aa["management_protocols"] = protocols

        # --- Session timeout ---
        timeout_line = root.find_line("console timeout ") or root.find_line("ssh timeout ")
        if timeout_line:
            m = re.search(r"timeout (\d+)", timeout_line)
            if m:
                aa["session_timeout_seconds"] = int(m.group(1)) * 60
        # Also check 'exec-timeout' for console
        for block in root.find_blocks("line "):
            exec_to = block.find_line("exec-timeout ")
            if exec_to:
                m = re.search(r"exec-timeout (\d+)\s*(\d*)", exec_to)
                if m:
                    mins = int(m.group(1))
                    secs = int(m.group(2)) if m.group(2) else 0
                    aa["session_timeout_seconds"] = mins * 60 + secs
                    break

        # --- Lockout ---
        aaa_lockout = root.find_line("aaa local authentication attempts max-fail ")
        if aaa_lockout:
            m = re.search(r"max-fail (\d+)", aaa_lockout)
            if m:
                aa["max_login_attempts"] = int(m.group(1))

        # --- Trusted hosts (ssh/http access lists) ---
        trusted: set[str] = set()
        for line in ssh_lines:
            m = re.match(r"ssh (\d[\d.]+) (\d[\d.]+) \S+", line)
            if m:
                trusted.add(_ip_mask_to_cidr(m.group(1), m.group(2)))
        aa["trusted_hosts"] = sorted(trusted)

        # --- Banner ---
        banner_lines: list[str] = []
        in_banner = False
        for line in root.lines():
            if line.startswith("banner "):
                banner_text = line[7:].strip()  # "banner motd ..." or "banner login ..."
                if banner_text:
                    banner_lines.append(banner_text)
        aa["banner"] = " ".join(banner_lines) if banner_lines else None
        aa["banner_enabled"] = bool(banner_lines)

        # --- SNMP ---
        snmp_server = root.find_line("snmp-server enable") is not None or bool(root.find_lines("snmp-server host "))
        aa["snmp"]["enabled"] = snmp_server
        communities = []
        for line in root.find_lines("snmp-server community "):
            community = _val(line, "snmp-server community")
            if community:
                communities.append(community.split()[0])
        aa["snmp"]["community_strings"] = communities

        # SNMP version
        if root.find_line("snmp-server enable traps snmp") or root.find_lines("snmp-server community"):
            aa["snmp"]["version"] = "v2c"
        snmpv3_lines = root.find_lines("snmp-server user ")
        if snmpv3_lines:
            aa["snmp"]["version"] = "v3"
            # Determine security level from first v3 user definition
            # "snmp-server user <n> <grp> v3 auth sha <k> priv aes 128 <k>"
            has_auth = any(" auth " in ln for ln in snmpv3_lines)
            has_priv = any(" priv " in ln for ln in snmpv3_lines)
            if has_auth and has_priv:
                aa["snmp"]["security_level"] = "auth-priv"
            elif has_auth:
                aa["snmp"]["security_level"] = "auth-no-priv"
            else:
                aa["snmp"]["security_level"] = "no-auth-no-priv"

    def _get_ssh_port(self, root: _Block) -> int:
        line = root.find_line("ssh port ")
        if line:
            m = re.search(r"ssh port (\d+)", line)
            if m:
                return int(m.group(1))
        return 22

    def _extract_authentication(self, root: _Block, ir: dict) -> None:
        auth = ir["authentication"]

        # --- Local users ---
        users: list[dict] = []
        default_admin_exists = False

        for line in root.find_lines("username "):
            m = re.match(r"username\s+(\S+)\s+(.*)", line)
            if not m:
                continue
            username = m.group(1)
            rest = m.group(2)

            if username.lower() in ("admin", "cisco", "pix"):
                default_admin_exists = True

            priv_m = re.search(r"privilege\s+(\d+)", rest)
            priv = int(priv_m.group(1)) if priv_m else 1

            # Password hash detection
            hash_algo = None
            if "password " in rest:
                pwd_m = re.search(r"(?:password|secret)\s+(\d+)\s+(\S+)", rest)
                if pwd_m:
                    enc_type = int(pwd_m.group(1))
                    type_map = {0: "plaintext", 5: "md5", 7: "cisco_type7", 8: "pbkdf2_sha256", 9: "scrypt"}
                    hash_algo = type_map.get(enc_type, f"type_{enc_type}")
            elif "secret " in rest:
                hash_algo = "type5_md5"

            users.append({
                "username": username,
                "privilege_level": priv,
                "mfa_enabled": False,
                "password_hash_algorithm": hash_algo,
                "account_enabled": True,
            })

        auth["local_users"] = users
        auth["default_admin_account_exists"] = default_admin_exists
        auth["default_admin_renamed"] = not default_admin_exists

        # --- Password policy ---
        pp = auth["password_policy"]
        for line in root.find_lines("password-policy "):
            if "minimum-length" in line:
                m = re.search(r"minimum-length\s+(\d+)", line)
                if m:
                    pp["min_length"] = int(m.group(1))
            if "minimum-changes" in line:
                pass
            if "minimum-uppercase" in line:
                pp["require_uppercase"] = True
            if "minimum-lowercase" in line:
                pp["require_lowercase"] = True
            if "minimum-numeric" in line:
                pp["require_numbers"] = True
            if "minimum-special" in line:
                pp["require_special"] = True
            if "maximum-age" in line:
                m = re.search(r"maximum-age\s+(\d+)", line)
                if m:
                    pp["max_age_days"] = int(m.group(1))
            if "lifetime" in line:
                m = re.search(r"lifetime\s+(\d+)", line)
                if m:
                    pp["max_age_days"] = int(m.group(1))

        # --- Remote auth ---
        ra = auth["remote_auth"]
        for line in root.find_lines("aaa-server "):
            if "RADIUS" in line.upper() or "radius" in line.lower():
                ra["radius_enabled"] = True
            if "TACACS" in line.upper() or "tacacs" in line.lower():
                ra["tacacs_enabled"] = True
            if "LDAP" in line.upper() or "ldap" in line.lower():
                ra["ldap_enabled"] = True

    def _extract_logging(self, root: _Block, ir: dict) -> None:
        log = ir["logging"]

        # --- Syslog ---
        syslog_servers: list[dict] = []
        for line in root.find_lines("logging host "):
            # "logging host <interface> <ip> [tcp/udp/17] [port <port>]"
            parts = line.split()
            # parts: ['logging', 'host', '<interface>', '<ip>', ...]
            if len(parts) >= 4:
                host = parts[3]
                port = 514
                protocol = "udp"
                for i, p in enumerate(parts):
                    if p in ("tcp", "udp"):
                        protocol = p
                    if p == "port" and i + 1 < len(parts):
                        try:
                            port = int(parts[i + 1])
                        except ValueError:
                            pass
                    # tcp/514 style notation
                    m = re.match(r"(tcp|udp)/(\d+)", p)
                    if m:
                        protocol = m.group(1)
                        port = int(m.group(2))
                syslog_servers.append({
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                    "facility": None,
                    "severity": None,
                })

        log["syslog_servers"] = syslog_servers
        log["local_logging_enabled"] = root.find_line("logging enable") is not None

        log["log_traffic"] = root.find_line("logging permit-hostdown") is not None \
            or bool(root.find_lines("access-list.*log"))

        # --- NTP ---
        ntp_servers: list[str] = []
        for line in root.find_lines("ntp server "):
            m = re.match(r"ntp server\s+(\S+)", line)
            if m:
                ntp_servers.append(m.group(1))
        log["ntp_servers"] = ntp_servers
        log["ntp_enabled"] = len(ntp_servers) > 0

    def _extract_vpn(self, root: _Block, ir: dict) -> None:
        vpn = ir["vpn"]

        # --- IKEv1 crypto maps & policies ---
        # IKEv2 policies
        ikev2_policies = self._parse_ikev2_policies(root)
        ikev1_policies = self._parse_ikev1_policies(root)

        # Crypto maps → tunnels
        tunnels: list[dict] = []
        seen_peers: set[str] = set()

        for cm_block in root.find_blocks("crypto map "):
            # "crypto map <name> <seq> ipsec-isakmp"
            m = re.match(r"crypto map (\S+) (\d+) ipsec-isakmp", cm_block.header)
            if not m:
                continue

            peer_line = cm_block.find_line("set peer ")
            peer = _val(peer_line, "set peer") if peer_line else None
            if not peer or peer in seen_peers:
                continue
            seen_peers.add(peer)

            # Transform set
            transform_line = cm_block.find_line("set transform-set ")
            transform_name = _val(transform_line, "set transform-set") if transform_line else ""
            enc, auth = self._lookup_transform(root, transform_name or "")

            # IKEv2 profile reference
            ikev2_profile = cm_block.find_line("set ikev2 ipsec-proposal ")
            is_ikev2 = ikev2_profile is not None or cm_block.find_line("set ikev2-profile") is not None

            # IKEv1 policy for this map — look at matching ISAKMP policy
            ike_version = 2 if is_ikev2 else 1
            p1_policy = self._best_ike_policy(ikev2_policies if is_ikev2 else ikev1_policies)

            # PFS
            pfs_line = cm_block.find_line("set pfs ")
            pfs_group = _re_val(pfs_line, r"group(\d+)") if pfs_line else None
            pfs_dh = [int(pfs_group)] if pfs_group else []
            pfs_enabled = pfs_line is not None

            # IKEv1 aggressive mode: "crypto isakmp aggressive-mode disable" disables it;
            # absence means it could be on. Check for explicit disable.
            aggressive_disabled = root.find_line("crypto isakmp aggressive-mode disable") is not None
            aggressive_mode = (ike_version == 1) and not aggressive_disabled

            tunnels.append({
                "name": f"{m.group(1)}/{m.group(2)}",
                "enabled": True,
                "remote_gateway": peer,
                "phase1": {
                    "encryption": p1_policy.get("encryption", []),
                    "authentication": p1_policy.get("authentication", []),
                    "dh_groups": p1_policy.get("dh_groups", []),
                    "lifetime_seconds": p1_policy.get("lifetime_seconds"),
                    "pfs_enabled": pfs_enabled,
                    "ike_version": ike_version,
                    "aggressive_mode": aggressive_mode,
                },
                "phase2": {
                    "encryption": enc,
                    "authentication": auth,
                    "dh_groups": pfs_dh,
                    "lifetime_seconds": None,
                    "pfs_enabled": pfs_enabled,
                },
                "auth_method": "psk" if root.find_line(f"crypto isakmp key") else "certificate",
            })

        # Also check tunnel-group for IKEv2
        for tg_block in root.find_blocks("tunnel-group "):
            m = re.match(r"tunnel-group (\S+) type ipsec-l2l", tg_block.header)
            if m:
                peer = m.group(1)
                if peer not in seen_peers:
                    seen_peers.add(peer)
                    tunnels.append({
                        "name": f"tg-{peer}",
                        "enabled": True,
                        "remote_gateway": peer,
                        "phase1": {
                            "encryption": [],
                            "authentication": [],
                            "dh_groups": [],
                            "lifetime_seconds": None,
                            "pfs_enabled": None,
                            "ike_version": 2,
                        },
                        "phase2": {"encryption": [], "authentication": [], "dh_groups": [], "lifetime_seconds": None, "pfs_enabled": None},
                        "auth_method": "psk",
                    })

        vpn["ipsec_tunnels"] = tunnels

        # --- SSL VPN (AnyConnect/WebVPN) ---
        ssl_vpn = vpn["ssl_vpn"]
        webvpn_block = root.find_block("webvpn")
        anyconnect = root.find_block("anyconnect") or root.find_block("webvpn")
        if webvpn_block or anyconnect:
            ssl_vpn["enabled"] = True
            tls_line = root.find_line("ssl server-version ")
            if tls_line:
                ssl_vpn["tls_versions"] = self._parse_tls_versions(_val(tls_line, "ssl server-version") or "")
            else:
                ssl_vpn["tls_versions"] = ["TLSv1.2", "TLSv1.3"]

    def _parse_ikev2_policies(self, root: _Block) -> list[dict]:
        policies: list[dict] = []
        for block in root.find_blocks("crypto ikev2 policy "):
            enc_lines = block.find_lines("encryption ")
            int_lines = block.find_lines("integrity ")
            group_lines = block.find_lines("group ")
            lt_line = block.find_line("lifetime seconds ")
            encryptions = [_val(l, "encryption") or "" for l in enc_lines]
            integrity = [_val(l, "integrity") or "" for l in int_lines]
            groups = []
            for gl in group_lines:
                for part in (gl.replace("group", "")).split():
                    try:
                        groups.append(int(part))
                    except ValueError:
                        pass
            lt = None
            if lt_line:
                m = re.search(r"(\d+)", lt_line)
                lt = int(m.group(1)) if m else None
            policies.append({
                "encryption": [e.lower() for e in encryptions if e],
                "authentication": [i.lower() for i in integrity if i],
                "dh_groups": groups,
                "lifetime_seconds": lt,
            })
        return policies

    def _parse_ikev1_policies(self, root: _Block) -> list[dict]:
        policies: list[dict] = []
        for block in root.find_blocks("crypto isakmp policy "):
            enc_line = block.find_line("encryption ")
            hash_line = block.find_line("hash ")
            group_line = block.find_line("group ")
            lt_line = block.find_line("lifetime ")
            enc = [_val(enc_line, "encryption").lower()] if enc_line and _val(enc_line, "encryption") else []
            hsh = [_val(hash_line, "hash").lower()] if hash_line and _val(hash_line, "hash") else []
            grp = []
            if group_line:
                m = re.search(r"group (\d+)", group_line)
                if m:
                    grp = [int(m.group(1))]
            lt = None
            if lt_line:
                m = re.search(r"(\d+)", lt_line)
                lt = int(m.group(1)) if m else None
            policies.append({
                "encryption": enc,
                "authentication": hsh,
                "dh_groups": grp,
                "lifetime_seconds": lt,
            })
        return policies

    def _best_ike_policy(self, policies: list[dict]) -> dict:
        """Return the first policy (lowest priority number = first in list)."""
        return policies[0] if policies else {}

    def _lookup_transform(self, root: _Block, name: str) -> tuple[list[str], list[str]]:
        """Look up a crypto ipsec transform-set by name and return (enc, auth) lists."""
        for block in root.find_blocks("crypto ipsec transform-set "):
            m = re.match(r"crypto ipsec transform-set (\S+)\s+(.*)", block.header)
            if m and (not name or m.group(1) == name.split()[0]):
                transforms = m.group(2).lower().split()
                enc: list[str] = []
                auth: list[str] = []
                for t in transforms:
                    if any(x in t for x in ("esp-aes", "esp-des", "esp-3des", "esp-null")):
                        enc.append(t.replace("esp-", ""))
                    elif any(x in t for x in ("hmac", "sha", "md5", "aes-xcbc")):
                        auth.append(t.replace("esp-", "").replace("-hmac", ""))
                return enc, auth
        return [], []

    def _extract_firewall_policies(self, root: _Block, ir: dict) -> None:
        """Parse access-list entries and access-group assignments into policies."""
        # Collect all ACL entries by ACL name
        acls: dict[str, list[dict]] = defaultdict(list)

        for line in root.find_lines("access-list "):
            # "access-list <name> extended permit|deny <proto> <src> <dst> [log]"
            m = re.match(
                r"access-list (\S+) extended (permit|deny)\s+(.*)",
                line,
            )
            if not m:
                # "access-list <name> remark ..."
                continue
            acl_name = m.group(1)
            action = "allow" if m.group(2) == "permit" else "deny"
            rest = m.group(3)

            logged = rest.endswith(" log") or " log " in rest

            # Parse protocol and source/dest — simplified
            parts = rest.split()
            protocol = parts[0] if parts else "ip"
            src_addr, src_port, dst_addr, dst_port, rest_parts = self._parse_acl_src_dst(parts[1:])

            acls[acl_name].append({
                "action": action,
                "protocol": protocol,
                "src_addr": src_addr,
                "dst_addr": dst_addr,
                "src_port": src_port,
                "dst_port": dst_port,
                "logged": logged,
            })

        # Map ACLs to interfaces via access-group
        iface_acl: dict[str, tuple[str, str]] = {}  # iface -> (acl_name, direction)
        for line in root.find_lines("access-group "):
            # "access-group <name> in|out interface <iface>"
            m = re.match(r"access-group (\S+) (in|out) interface (\S+)", line)
            if m:
                iface_acl[m.group(3)] = (m.group(1), m.group(2))

        policies: list[dict] = []
        rule_idx = 0
        for iface, (acl_name, direction) in iface_acl.items():
            for entry in acls.get(acl_name, []):
                rule_idx += 1
                policies.append({
                    "id": rule_idx,
                    "name": f"{acl_name}/{rule_idx}",
                    "enabled": True,
                    "action": entry["action"],
                    "source_zones": [iface] if direction == "in" else [],
                    "destination_zones": [iface] if direction == "out" else [],
                    "source_addresses": [entry["src_addr"]],
                    "destination_addresses": [entry["dst_addr"]],
                    "services": [entry["protocol"]],
                    "protocols": [entry["protocol"]],
                    "source_ports": [entry["src_port"]] if entry["src_port"] else [],
                    "destination_ports": [entry["dst_port"]] if entry["dst_port"] else [],
                    "logging_enabled": entry["logged"],
                    "comment": None,
                    "schedule": None,
                    "nat_enabled": False,
                })

        # Also parse 'global access-list' (interface-independent)
        for line in root.find_lines("access-group "):
            if line.endswith(" global"):
                m = re.match(r"access-group (\S+) global", line)
                if m:
                    for entry in acls.get(m.group(1), []):
                        rule_idx += 1
                        policies.append({
                            "id": rule_idx,
                            "name": f"{m.group(1)}-global/{rule_idx}",
                            "enabled": True,
                            "action": entry["action"],
                            "source_zones": [],
                            "destination_zones": [],
                            "source_addresses": [entry["src_addr"]],
                            "destination_addresses": [entry["dst_addr"]],
                            "services": [entry["protocol"]],
                            "protocols": [entry["protocol"]],
                            "source_ports": [],
                            "destination_ports": [],
                            "logging_enabled": entry["logged"],
                            "comment": None,
                            "schedule": None,
                            "nat_enabled": False,
                        })

        ir["firewall_policies"] = policies

    def _parse_acl_src_dst(
        self, parts: list[str]
    ) -> tuple[str, str | None, str, str | None, list[str]]:
        """Extract source address, source port, dest address, dest port from ACL tokens."""
        def consume_addr(tokens: list[str]) -> tuple[str, list[str]]:
            if not tokens:
                return "any", []
            if tokens[0] == "any" or tokens[0] == "any4" or tokens[0] == "any6":
                return "all", tokens[1:]
            if tokens[0] == "host":
                return tokens[1] if len(tokens) > 1 else "host", tokens[2:]
            if tokens[0] == "object" or tokens[0] == "object-group":
                return tokens[1] if len(tokens) > 1 else tokens[0], tokens[2:]
            if len(tokens) >= 2:
                try:
                    # ip mask
                    return _ip_mask_to_cidr(tokens[0], tokens[1]), tokens[2:]
                except Exception:
                    pass
            return tokens[0], tokens[1:]

        def consume_port(tokens: list[str]) -> tuple[str | None, list[str]]:
            if not tokens or tokens[0] not in ("eq", "lt", "gt", "neq", "range", "object-group"):
                return None, tokens
            op = tokens[0]
            if op == "range" and len(tokens) >= 3:
                return f"{tokens[1]}-{tokens[2]}", tokens[3:]
            if op == "object-group" and len(tokens) >= 2:
                return tokens[1], tokens[2:]
            if len(tokens) >= 2:
                return tokens[1], tokens[2:]
            return None, tokens[1:]

        src_addr, parts = consume_addr(list(parts))
        src_port, parts = consume_port(parts)
        dst_addr, parts = consume_addr(parts)
        dst_port, parts = consume_port(parts)
        return src_addr, src_port, dst_addr, dst_port, parts

    def _extract_interfaces(self, root: _Block, ir: dict) -> None:
        interfaces: list[dict] = []
        for block in root.find_blocks("interface "):
            m = re.match(r"interface (\S+)", block.header)
            if not m:
                continue
            iface_name = m.group(1)
            if iface_name.startswith("Vlan") or iface_name.startswith("BVI"):
                iface_type = "vlan"
            elif iface_name.startswith("Tunnel"):
                iface_type = "tunnel"
            elif iface_name.startswith("Loopback"):
                iface_type = "loopback"
            else:
                iface_type = "physical"

            nameif = block.get_value("nameif ")
            ip_line = block.find_line("ip address ")
            ip_addr = None
            netmask = None
            if ip_line:
                parts = ip_line.split()[2:]  # strip "ip address"
                if len(parts) >= 2:
                    ip_addr = parts[0]
                    netmask = parts[1]

            shutdown = block.find_line("shutdown") is not None
            description = block.get_value("description ")

            # Management-access
            mgmt_access: list[str] = []
            if block.find_line("management-only") is not None:
                mgmt_access.append("management")
            if block.find_line("http") is not None:
                mgmt_access.append("https")
            if block.find_line("ssh") is not None:
                mgmt_access.append("ssh")

            interfaces.append({
                "name": iface_name,
                "type": iface_type,
                "role": infer_interface_role(nameif, iface_name),
                "zone": nameif,
                "ip_address": ip_addr,
                "netmask": netmask,
                "enabled": not shutdown,
                "management_access": mgmt_access,
                "description": description,
            })

        ir["interfaces"] = interfaces

    def _extract_network_objects(self, root: _Block, ir: dict) -> None:
        address_objects: list[dict] = []
        service_objects: list[dict] = []

        for block in root.find_blocks("object network "):
            m = re.match(r"object network (\S+)", block.header)
            if not m:
                continue
            name = m.group(1)
            host = block.get_value("host ")
            subnet = block.find_line("subnet ")
            fqdn = block.get_value("fqdn ")
            range_line = block.find_line("range ")
            if host:
                address_objects.append({"name": name, "type": "host", "value": host})
            elif subnet:
                parts = subnet.split()[1:]
                if len(parts) >= 2:
                    address_objects.append({"name": name, "type": "network",
                                            "value": _ip_mask_to_cidr(parts[0], parts[1])})
            elif fqdn:
                address_objects.append({"name": name, "type": "fqdn", "value": fqdn})
            elif range_line:
                parts = range_line.split()[1:]
                if len(parts) >= 2:
                    address_objects.append({"name": name, "type": "range", "value": f"{parts[0]}-{parts[1]}"})

        for block in root.find_blocks("object-group network "):
            m = re.match(r"object-group network (\S+)", block.header)
            if not m:
                continue
            name = m.group(1)
            members = block.find_lines("network-object ") + block.find_lines("group-object ")
            address_objects.append({"name": name, "type": "group",
                                    "value": ",".join(l.split()[-1] for l in members)})

        for block in root.find_blocks("object service "):
            m = re.match(r"object service (\S+)", block.header)
            if not m:
                continue
            name = m.group(1)
            svc_line = block.find_line("service ")
            if svc_line:
                parts = svc_line.split()[1:]
                proto = parts[0] if parts else ""
                port = parts[-1] if len(parts) > 1 else None
                service_objects.append({"name": name, "protocol": proto, "port_range": port})

        ir["network_objects"]["address_objects"] = address_objects
        ir["network_objects"]["service_objects"] = service_objects

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _parse_tls_versions(self, raw: str) -> list[str]:
        raw = raw.lower()
        mapping = {
            "tlsv1": "TLSv1.0",
            "tlsv1.1": "TLSv1.1",
            "tlsv1.2": "TLSv1.2",
            "tlsv1.3": "TLSv1.3",
        }
        versions: list[str] = []
        for k, v in mapping.items():
            if k in raw:
                versions.append(v)
        if not versions:
            return ["TLSv1.2", "TLSv1.3"]
        # If minimum is specified, include all higher versions
        if "TLSv1.2" in versions and "TLSv1.3" not in versions:
            versions.append("TLSv1.3")
        return sorted(set(versions))


# FTD in ASA compatibility mode uses the same parser
class CiscoFTDParser(CiscoASAParser):
    """Cisco FTD parser — identical to ASA parser in ASA compatibility mode."""
    vendor = "cisco_ftd"
