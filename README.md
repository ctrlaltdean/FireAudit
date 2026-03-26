# FireAudit

Offline firewall configuration auditing tool with multi-vendor support and compliance framework mapping.

## Features

- **9 vendors supported**: FortiGate, Palo Alto, Cisco ASA/FTD, pfSense, OPNsense, SonicWall, Sophos XG, WatchGuard
- **14 built-in audit rules** covering admin access, authentication, logging, VPN, and firewall policies
- **4 compliance frameworks**: CIS, NIST 800-53, ISO 27001, CMMC/DFARS
- **HTML and JSON report output** with per-framework compliance scores
- **Interactive wizard mode** — no CLI flags required
- **Fully offline** — no external API calls, safe for air-gapped environments
- **Standalone Windows exe** — no Python installation required

## Quick Start

### Wizard (recommended)

```
fireaudit wizard
```

Walks you through vendor selection, config file, framework, and report output interactively.

### CLI

```bash
# Audit a FortiGate config against all rules
fireaudit audit -c firewall.conf -v fortigate

# Audit a Palo Alto with NIST 800-53 mapping, output HTML report
fireaudit audit -c running.xml -v paloalto -f nist_800-53 -o report.html

# Audit a SonicWall, filter to high+ severity findings only
fireaudit audit -c export.xml -v sonicwall -s high

# List all available rules
fireaudit rules list

# Parse config to normalized IR JSON
fireaudit parse -c firewall.conf -v fortigate -o ir.json
```

## Supported Vendors

| Vendor | Config Format | Vendor Flag |
|--------|--------------|-------------|
| FortiGate | `.conf` (FortiOS config backup) | `fortigate` |
| Palo Alto | XML (running config) | `paloalto` |
| Cisco ASA | Text (`show run` output) | `cisco_asa` |
| Cisco FTD | Text (`show run` output) | `cisco_ftd` |
| pfSense | XML (`config.xml`) | `pfsense` |
| OPNsense | XML (`config.xml`) | `opnsense` |
| SonicWall | XML (settings export) | `sonicwall` |
| Sophos XG | XML (backup file) | `sophos_xg` |
| WatchGuard | XML (policy backup) | `watchguard` |

## Audit Rules

Each rule describes a **required** security configuration. Severity indicates how critical the finding is when a rule **fails** (i.e. when the requirement is not met).

| Rule ID | Requirement | Severity if Failed |
|---------|-------------|--------------------|
| FW-ADM-001 | HTTP management must be disabled | High |
| FW-ADM-002 | Telnet management must be disabled | High |
| FW-ADM-003 | SSH must use version 2 only | Medium |
| FW-ADM-004 | Administrative session timeout must be 10 minutes or less | Medium |
| FW-ADM-005 | Administrative access must be restricted to trusted hosts | Medium |
| FW-ADM-006 | Login banner must be configured | Low |
| FW-AUTH-001 | Minimum password length must be 12 characters or more | High |
| FW-AUTH-002 | Default 'admin' account must be renamed or disabled | High |
| FW-LOG-001 | Remote syslog server must be configured | High |
| FW-LOG-002 | NTP must be configured for accurate log timestamps | Medium |
| FW-POL-001 | No unrestricted any-to-any allow policies | Critical |
| FW-POL-002 | All allow policies must have logging enabled | High |
| FW-VPN-001 | IPsec VPN must not use weak encryption algorithms (3DES/DES) | Critical |
| FW-VPN-002 | IPsec VPN tunnels must use IKEv2 | High |
| FW-VPN-003 | IPsec VPN must not use weak Diffie-Hellman groups (1/2/5) | High |
| FW-VPN-004 | SSL VPN must not accept TLS 1.0 or 1.1 | High |

## Compliance Frameworks

Rules are mapped to controls in:
- **CIS Benchmarks** (firewall hardening)
- **NIST SP 800-53** (AC, AU, CM, IA, SC controls)
- **ISO 27001:2022** (A.8.x controls)
- **CMMC 2.0 / DFARS** (AC, AU, CM, IA, SC domains)

## Installation

### From source (requires Python 3.11+)

```bash
pip install -e .
```

### Windows exe

Download `fireaudit.exe` from the [Releases](../../releases) page. No Python required.

To build the exe yourself:

```bash
pip install pyinstaller
python build_exe.py
# Output: dist/fireaudit.exe
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=fireaudit --cov-report=html
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All rules passed (or only low/info failures) |
| 1 | Error (parse failure, missing rules) |
| 2 | Critical or High severity failures found |

Exit code 2 makes FireAudit CI/CD pipeline friendly.

## License

MIT
