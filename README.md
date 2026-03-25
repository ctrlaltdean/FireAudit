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

| Rule ID | Name | Severity |
|---------|------|----------|
| FW-ADM-001 | HTTP management disabled | High |
| FW-ADM-002 | Telnet management disabled | High |
| FW-ADM-003 | SSH version 2 only | Medium |
| FW-ADM-004 | Admin session timeout ≤ 10 min | Medium |
| FW-ADM-005 | Trusted hosts configured | Medium |
| FW-ADM-006 | Login banner configured | Low |
| FW-AUTH-001 | Password minimum length ≥ 12 | High |
| FW-AUTH-002 | Default admin account renamed | High |
| FW-LOG-001 | Syslog server configured | High |
| FW-LOG-002 | NTP server configured | Medium |
| FW-POL-001 | No any/any allow rules | Critical |
| FW-POL-002 | All allow policies have logging | High |
| FW-VPN-001 | No weak IKE encryption (3DES/DES) | Critical |
| FW-VPN-002 | IKEv2 only (no IKEv1) | High |
| FW-VPN-003 | No weak DH groups (group 1/2/5) | High |
| FW-VPN-004 | SSL VPN requires TLS 1.2+ | High |

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
