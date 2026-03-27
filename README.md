# FireAudit

Offline firewall configuration auditing tool with multi-vendor support and compliance framework mapping.

## Features

- **11 vendors supported**: FortiGate, Palo Alto, Cisco ASA/FTD, pfSense, OPNsense, SonicWall, Sophos XG, WatchGuard, Check Point Gaia, Juniper SRX
- **61 audit rules** — 48 automated checks + 13 manual verification items covering admin access, authentication, logging, VPN, and firewall policies
- **4 compliance frameworks**: CIS, NIST 800-53, ISO 27001, CMMC/DFARS
- **HTML and JSON report output** with per-framework compliance scores and a dedicated manual checks section
- **Interactive wizard mode** — no CLI flags required
- **Fully offline** — no external API calls, safe for air-gapped environments
- **Standalone Windows exe** — no Python installation required

## Quick Start

### Wizard (recommended)

```
fireaudit wizard
```

Walks you through vendor selection, config file, framework, and report output interactively.

### CLI — Single device

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

### CLI — Bulk / fleet audit

Audit an entire directory of configs at once. Vendor is auto-detected per file.

```bash
# Audit all configs in a directory, write HTML reports + fleet summary
fireaudit bulk ./configs/

# Specify output directory and produce both HTML and JSON per device
fireaudit bulk ./configs/ --output-dir ./reports/ --format both

# Force vendor for all files (useful when auto-detect is ambiguous)
fireaudit bulk ./configs/fortigate/ --vendor fortigate

# Use 8 parallel workers for large fleets
fireaudit bulk ./configs/ --workers 8
```

Outputs per device:
- `<filename>.html` (or `.json`) — individual device report
- `fleet_summary.html` — fleet overview table sorted worst score first
- `fleet_summary.json` — machine-readable fleet results

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
| Check Point Gaia | Text (`show configuration` clish output) | `checkpoint` |
| Juniper SRX | Text (JunOS hierarchical `show configuration`) | `juniper_srx` |

### Vendor Auto-Detection

When using `fireaudit bulk` (or `fireaudit audit` without `-v`), FireAudit sniffs the first 4 KB of each file to identify the vendor automatically:

| Vendor | Detection Heuristic |
|--------|---------------------|
| FortiGate | `#config-version=FGT` header or `config system global` + `set hostname` |
| Check Point Gaia | `set hostname` + `set interface` + Gaia marker (`set gaia-version`, `set edition`, or `add syslog log-remote-address`) in non-XML file |
| Juniper SRX | `## Last changed:` comment header, or `version X.Y;` + `system {` block |
| Cisco ASA/FTD | `ASA`, `ASDM`, or `Cisco Adaptive Security` at line start |
| Palo Alto | `<config version=` + `<devices>` XML markers |
| pfSense | `<pfsense` XML root element |
| OPNsense | `<opnsense` XML root element |
| SonicWall | `<SonicwallSettings>` or `<SonicWALL>` XML element |
| Sophos XG | `<Configuration firmware_appliancekey=` or `<APPLIANCESettings>` |
| WatchGuard | `<policy>` or `<profile>` XML root with `WatchGuard` or `<setup>` markers |

## Audit Rules

Each rule describes a **required** security configuration. Severity indicates how critical the finding is when a rule **fails** (i.e. when the requirement is not met).

### Automated Checks (48 rules)

#### Administration
| Rule ID | Requirement | Severity if Failed |
|---------|-------------|---------------------|
| FW-ADM-001 | HTTP management must be disabled | Critical |
| FW-ADM-002 | Telnet management must be disabled | Critical |
| FW-ADM-003 | SSH must use version 2 only | High |
| FW-ADM-004 | Administrative session timeout must be 10 minutes or less | Medium |
| FW-ADM-005 | Administrative access must be restricted to trusted hosts | High |
| FW-ADM-006 | Login banner must be configured | Low |
| FW-ADM-007 | SNMP v1 and v2c must be disabled | Critical |
| FW-ADM-008 | HTTPS management must use TLS 1.2 or higher | High |
| FW-ADM-009 | Administrative login lockout must be configured | High |
| FW-ADM-010 | SNMPv3 must use authPriv security level | High |
| FW-ADM-011 | HTTPS management must not be exposed on WAN interfaces | Critical |
| FW-ADM-012 | SSH management must not be exposed on WAN interfaces | Critical |
| FW-ADM-013 | SNMP must be restricted to authorized management hosts | High |
| FW-ADM-014 | SSH must not use weak ciphers or MACs | Medium |

#### Authentication
| Rule ID | Requirement | Severity if Failed |
|---------|-------------|---------------------|
| FW-AUTH-001 | Minimum password length must be 12 characters or more | High |
| FW-AUTH-002 | Default 'admin' account must be renamed or disabled | High |
| FW-AUTH-003 | Password complexity requirements must be enforced | Medium |
| FW-AUTH-004 | Password history must prevent reuse of last 5 passwords | Medium |
| FW-AUTH-005 | Account lockout threshold must be 5 attempts or fewer | High |
| FW-AUTH-006 | Multi-factor authentication must be required for administrative access | High |
| FW-AUTH-007 | Centralized authentication (RADIUS or TACACS+) must be configured | Medium |
| FW-AUTH-009 | Password maximum age must be enforced (90 days or fewer) | Medium |

#### Logging
| Rule ID | Requirement | Severity if Failed |
|---------|-------------|---------------------|
| FW-LOG-001 | Remote syslog server must be configured | High |
| FW-LOG-002 | NTP must be configured for accurate log timestamps | Medium |
| FW-LOG-003 | Denied traffic must be logged | High |
| FW-LOG-004 | Authentication events must be logged | Medium |
| FW-LOG-005 | Administrative configuration changes must be logged | Medium |
| FW-LOG-006 | Syslog must use encrypted transport (TLS) | Medium |
| FW-LOG-007 | Multiple syslog servers should be configured for redundancy | Low |

#### Firewall Policies
| Rule ID | Requirement | Severity if Failed |
|---------|-------------|---------------------|
| FW-POL-001 | No unrestricted any-to-any allow policies | Critical |
| FW-POL-002 | All allow policies must have logging enabled | High |
| FW-POL-003 | An explicit deny rule must exist in the policy | Critical |
| FW-POL-004 | Deny rules must have logging enabled | Medium |
| FW-POL-005 | All allow rules must have a descriptive comment | Low |
| FW-POL-010 | Allow rules must not permit all services (service=any) | High |

#### VPN
| Rule ID | Requirement | Severity if Failed |
|---------|-------------|---------------------|
| FW-VPN-001 | IPsec VPN must not use weak encryption algorithms (3DES/DES) | Critical |
| FW-VPN-002 | IPsec VPN tunnels must use IKEv2 | High |
| FW-VPN-003 | IPsec VPN must not use weak Diffie-Hellman groups (1/2/5) | High |
| FW-VPN-004 | SSL VPN must not accept TLS 1.0 or 1.1 | High |
| FW-VPN-005 | IPsec Phase 1 must not use weak integrity algorithms (MD5/SHA-1) | Critical |
| FW-VPN-006 | IPsec Phase 2 must not use weak integrity algorithms (MD5/SHA-1) | High |
| FW-VPN-007 | IPsec VPN must have Perfect Forward Secrecy enabled | High |
| FW-VPN-008 | IKEv1 aggressive mode must be disabled | High |
| FW-VPN-009 | SSL VPN must require multi-factor authentication | High |
| FW-VPN-010 | SSL VPN split tunneling must be disabled or restricted | Medium |
| FW-VPN-011 | IPsec Phase 1 (IKE SA) lifetime must not exceed 86400 seconds | Medium |
| FW-VPN-012 | IPsec Phase 2 (IPsec SA) lifetime must not exceed 3600 seconds | Medium |
| FW-VPN-013 | IPsec VPN must use certificate authentication instead of pre-shared keys | Medium |

### Manual Verification Checklist (13 items)

The following checks require human review and cannot be determined from static configuration analysis alone. They appear as a dedicated section in the HTML report.

| Rule ID | Check |
|---------|-------|
| FW-MAN-001 | IPS/IDS signatures and profiles must be reviewed and active |
| FW-MAN-002 | SSL/TLS deep inspection must be configured for outbound traffic |
| FW-MAN-003 | Unused and stale firewall rules must be removed |
| FW-MAN-004 | Firewall firmware must be on a supported and patched version |
| FW-MAN-005 | Configuration backups must be scheduled, tested, and stored securely |
| FW-MAN-006 | High availability failover must be tested periodically |
| FW-MAN-007 | DoS/DDoS protection profiles must be configured |
| FW-MAN-008 | Application control policy must be configured and enforced |
| FW-MAN-009 | Remote access VPN must enforce endpoint posture checking |
| FW-MAN-010 | Physical access to firewall hardware must be restricted |
| FW-MAN-011 | IKEv1 aggressive mode must be confirmed disabled (cross-vendor) |
| FW-MAN-012 | Anti-spoofing (uRPF) must be enabled on WAN interfaces |
| FW-MAN-013 | Firewall rules must be reviewed against business requirements annually |

## Compliance Frameworks

Rules are mapped to controls in:
- **CIS Benchmarks** (firewall hardening)
- **NIST SP 800-53** (AC, AU, CM, IA, SC controls)
- **NIST CSF** (PR.AC, PR.DS, DE.CM subcategories)
- **DISA Network Infrastructure SRG** (SRG-NET-XXXXXX requirement IDs)
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

## Posture Scoring

Every audit (single and bulk) produces a weighted posture score:

| Severity | Deduction per FAIL |
|----------|--------------------|
| Critical | −20 pts |
| High | −10 pts |
| Medium | −4 pts |
| Low | −1 pt |

Score starts at 100 and floors at 0. Grade thresholds:

| Grade | Score |
|-------|-------|
| A | 90–100 |
| B | 75–89 |
| C | 60–74 |
| D | 40–59 |
| F | 0–39 |

`not_applicable` and `manual_check` findings do not affect the score.

In bulk mode, the **fleet posture score** is the arithmetic mean of all device scores.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All rules passed (or only low/info failures) |
| 1 | Error (parse failure, missing rules, or bulk with errors) |
| 2 | Critical or High severity failures found (bulk: any device scores below 60) |

Exit code 2 makes FireAudit CI/CD pipeline friendly.

## License

MIT
