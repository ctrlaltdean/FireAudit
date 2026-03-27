"""One-time script: inject DISA_STIG framework entries into all rule YAML files.

Run from the repo root:
    python add_disa_stig.py
"""

import pathlib
import re

RULES_DIR = pathlib.Path("rules")

# Network Infrastructure Policy SRG (SRG-NET) mappings per rule.
# Text format: "SRG-NET-XXXXXX: brief requirement summary"
DISA_MAPPINGS: dict[str, list[str]] = {
    # --- Administration ---
    "FW-ADM-001": [
        "SRG-NET-000019: The network device must not use unencrypted protocols for management access",
    ],
    "FW-ADM-002": [
        "SRG-NET-000023: The network device must terminate all unencrypted remote management connections",
    ],
    "FW-ADM-003": [
        "SRG-NET-000026: The network device must use FIPS-validated cryptography for SSH sessions",
    ],
    "FW-ADM-004": [
        "SRG-NET-000045: The network device must terminate idle management sessions after no more than 10 minutes",
    ],
    "FW-ADM-005": [
        "SRG-NET-000049: The network device must limit management connections to authorized IP addresses",
    ],
    "FW-ADM-006": [
        "SRG-NET-000062: The network device must display a DOD-approved warning banner before granting access",
    ],
    "FW-ADM-007": [
        "SRG-NET-000131: The network device must prohibit the use of SNMP v1 and v2c",
    ],
    "FW-ADM-008": [
        "SRG-NET-000339: The network device must use FIPS-validated cryptography for HTTPS management sessions",
    ],
    "FW-ADM-009": [
        "SRG-NET-000167: The network device must enforce a limit of consecutive failed login attempts",
    ],
    "FW-ADM-010": [
        "SRG-NET-000131: The network device must use SNMPv3 with authentication and privacy (authPriv)",
    ],
    # --- Authentication ---
    "FW-AUTH-001": [
        "SRG-NET-000213: The network device must enforce a minimum 15-character password length",
    ],
    "FW-AUTH-002": [
        "SRG-NET-000166: The network device must prohibit the use of default or shared accounts",
    ],
    "FW-AUTH-003": [
        "SRG-NET-000214: The network device must enforce password complexity requirements",
    ],
    "FW-AUTH-004": [
        "SRG-NET-000215: The network device must prohibit password reuse for a minimum of five generations",
    ],
    "FW-AUTH-005": [
        "SRG-NET-000205: The network device must enforce an account lockout after failed authentication attempts",
    ],
    "FW-AUTH-006": [
        "SRG-NET-000138: The network device must enforce multifactor authentication for administrative access",
    ],
    "FW-AUTH-007": [
        "SRG-NET-000193: The network device must use an authentication server to authenticate administrators",
    ],
    # --- Logging ---
    "FW-LOG-001": [
        "SRG-NET-000333: The network device must send log data to a central log server",
    ],
    "FW-LOG-002": [
        "SRG-NET-000255: The network device must synchronize internal clocks using an authoritative NTP server",
    ],
    "FW-LOG-003": [
        "SRG-NET-000334: The network device must generate audit records for denied network traffic",
    ],
    "FW-LOG-004": [
        "SRG-NET-000089: The network device must generate audit records for authentication events",
    ],
    "FW-LOG-005": [
        "SRG-NET-000089: The network device must generate audit records for all configuration changes",
    ],
    "FW-LOG-006": [
        "SRG-NET-000333: The network device must use encryption when transmitting log data to remote servers",
    ],
    "FW-LOG-007": [
        "SRG-NET-000333: The network device must use redundant log servers for availability",
    ],
    # --- Firewall Policies ---
    "FW-POL-001": [
        "SRG-NET-000230: The firewall must deny network communications traffic by default and allow traffic by exception",
    ],
    "FW-POL-002": [
        "SRG-NET-000334: The firewall must generate audit records for traffic matching allow rules",
    ],
    "FW-POL-003": [
        "SRG-NET-000230: The firewall must have an explicit deny-all rule as the last rule in the policy",
    ],
    "FW-POL-004": [
        "SRG-NET-000334: The firewall must generate audit records for traffic matching deny rules",
    ],
    "FW-POL-005": [
        "SRG-NET-000230: The firewall must have documented rules with a business justification for each allow rule",
    ],
    # --- VPN ---
    "FW-VPN-001": [
        "SRG-NET-000280: The VPN gateway must use FIPS-validated cryptography for IPsec encryption",
    ],
    "FW-VPN-002": [
        "SRG-NET-000280: The VPN gateway must use IKEv2 for IPsec tunnel establishment",
    ],
    "FW-VPN-003": [
        "SRG-NET-000280: The VPN gateway must use Diffie-Hellman groups of 14 or higher for key exchange",
    ],
    "FW-VPN-004": [
        "SRG-NET-000339: The SSL VPN must use TLS 1.2 or higher and reject connections using TLS 1.0 or 1.1",
    ],
    "FW-VPN-005": [
        "SRG-NET-000280: The VPN gateway must use FIPS-approved integrity algorithms for IPsec Phase 1",
    ],
    "FW-VPN-006": [
        "SRG-NET-000280: The VPN gateway must use FIPS-approved integrity algorithms for IPsec Phase 2",
    ],
    "FW-VPN-007": [
        "SRG-NET-000281: The VPN gateway must enable Perfect Forward Secrecy for IPsec tunnels",
    ],
    "FW-VPN-008": [
        "SRG-NET-000280: The VPN gateway must not use IKEv1 aggressive mode",
    ],
    "FW-VPN-009": [
        "SRG-NET-000138: The SSL VPN must enforce multifactor authentication for remote access",
    ],
    "FW-VPN-010": [
        "SRG-NET-000231: The VPN client must not permit split tunneling unless explicitly approved",
    ],
    # --- Manual Checks ---
    "FW-MAN-001": [
        "SRG-NET-000230: The network device must implement intrusion detection or prevention mechanisms",
    ],
    "FW-MAN-002": [
        "SRG-NET-000338: The firewall must inspect encrypted traffic using SSL/TLS decryption",
    ],
    "FW-MAN-003": [
        "SRG-NET-000230: The firewall must not retain rules that are unused or no longer required",
    ],
    "FW-MAN-004": [
        "SRG-NET-000006: The network device must run a vendor-supported software release",
    ],
    "FW-MAN-005": [
        "SRG-NET-000070: The network device must have its configuration backed up and tested regularly",
    ],
    "FW-MAN-006": [
        "SRG-NET-000008: The network device must support high-availability failover and be tested periodically",
    ],
    "FW-MAN-007": [
        "SRG-NET-000230: The network device must implement DoS and DDoS protection mechanisms",
    ],
    "FW-MAN-008": [
        "SRG-NET-000230: The firewall must enforce application-layer filtering policies",
    ],
    "FW-MAN-009": [
        "SRG-NET-000280: The VPN gateway must enforce endpoint compliance checking before granting remote access",
    ],
    "FW-MAN-010": [
        "SRG-NET-000001: The network device must be located in a physically controlled access area",
    ],
    "FW-MAN-011": [
        "SRG-NET-000280: The VPN gateway must not use IKEv1 aggressive mode (cross-vendor verification)",
    ],
    "FW-MAN-012": [
        "SRG-NET-000230: The network device must implement anti-spoofing mechanisms on WAN interfaces",
    ],
    "FW-MAN-013": [
        "SRG-NET-000230: The firewall rule base must be reviewed against business requirements at least annually",
    ],
}


def build_disa_block(entries: list[str]) -> str:
    """Return the YAML text block for DISA_STIG to insert."""
    lines = ["  DISA_STIG:"]
    for entry in entries:
        lines.append(f'    - "{entry}"')
    return "\n".join(lines) + "\n"


def inject_disa_stig(file_path: pathlib.Path, rule_id: str) -> bool:
    """Insert DISA_STIG into *file_path* if not already present. Returns True if modified."""
    entries = DISA_MAPPINGS.get(rule_id)
    if not entries:
        print(f"  SKIP {rule_id}: no DISA mapping defined")
        return False

    text = file_path.read_text(encoding="utf-8")

    if "DISA_STIG:" in text:
        print(f"  SKIP {rule_id}: DISA_STIG already present")
        return False

    # Insert the DISA_STIG block immediately before the `match:` top-level key
    match_re = re.compile(r"^match:", re.MULTILINE)
    m = match_re.search(text)
    if not m:
        print(f"  WARN {rule_id}: could not locate `match:` key in {file_path.name}")
        return False

    insert_pos = m.start()
    new_text = text[:insert_pos] + build_disa_block(entries) + text[insert_pos:]
    file_path.write_text(new_text, encoding="utf-8")
    print(f"  OK   {rule_id}: DISA_STIG injected into {file_path.name}")
    return True


def main() -> None:
    modified = 0
    for yaml_file in sorted(RULES_DIR.rglob("*.yaml")):
        # Extract rule_id from first line of file (fast, avoids full yaml parse)
        first_lines = yaml_file.read_text(encoding="utf-8", errors="replace")
        rid_match = re.search(r"^rule_id:\s*(\S+)", first_lines, re.MULTILINE)
        if not rid_match:
            print(f"  WARN: no rule_id found in {yaml_file}")
            continue
        rule_id = rid_match.group(1)
        if inject_disa_stig(yaml_file, rule_id):
            modified += 1

    print(f"\nDone: {modified} files updated.")


if __name__ == "__main__":
    main()
