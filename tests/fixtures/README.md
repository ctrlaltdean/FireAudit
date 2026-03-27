# FireAudit Test Fixtures

This directory contains firewall configuration fixtures used for parser and rule-engine testing.
Each vendor subdirectory contains both real (downloaded from public repositories) and
synthetic (generated) fixtures.

---

## Vendors with Real Public Samples

### FortiGate (`fortigate/`)

| File | Source URL | Notable Characteristics |
|------|-----------|------------------------|
| `directfire_fortigate.conf` | https://raw.githubusercontent.com/glennake/DirectFire_Converter/master/tests/fortigate/fortigate.conf | FortiOS CLI format; 884 lines; real home/SMB device config; has SNMP community "public", 1 firewall policy, 6 interfaces (WAN + LAN), no IPsec VPN, no syslog configured |
| `sample_full.conf` | Synthetic (pre-existing) | Synthetic fixture with intentional security gaps and passing controls |

### WatchGuard (`watchguard/`)

| File | Source URL | Notable Characteristics |
|------|-----------|------------------------|
| `directfire_watchguard.xml` | https://raw.githubusercontent.com/glennake/DirectFire_Converter/master/tests/watchguard/watchguard.xml | **Old WatchGuard XML schema** (`<profile>` root, WatchGuard X-series style); 474 lines; uses `<policy-list>`, `<interface-list>` — does NOT match current Fireware parser schema (`<setup>`, `<policy-tag>`, `<logging>`) so parser extracts zero objects |
| `sample_policy.xml` | Synthetic (pre-existing) | Synthetic fixture with Fireware 12.x schema; has IPsec VPN, syslog, NTP |

### Cisco ASA (`cisco_asa/`)

| File | Source URL | Notable Characteristics |
|------|-----------|------------------------|
| `directfire_ciscoasa_pre83.conf` | https://raw.githubusercontent.com/glennake/DirectFire_Converter/master/tests/ciscoasa_pre83/ciscoasa_pre83.txt | ASA pre-8.3 format (old ACL syntax with object-groups); 147 lines; real production config snippet; has NTP (using named objects INSIDE1/INSIDE2), 6 interfaces, 6 ACL rules, no username/AAA config |
| `sample_running.conf` | Synthetic (pre-existing) | Synthetic fixture with full running-config format |

---

## Vendors With No Real Public Samples Found

The following vendors had no suitable public config files found in any of the surveyed repositories.
Synthetic fixtures were generated based on vendor documentation and parser expected element names.

### Palo Alto (`paloalto/`)

- **Searched**: `PaloAltoNetworks/iron-skillet` (repo not found / access denied), `moshekaplan/palo_alto_firewall_analyzer` (only a .cfg metadata file found, not PAN-OS XML)
- **Status**: Only pre-existing synthetic fixture available

| File | Source | Notable Characteristics |
|------|--------|------------------------|
| `sample_running.xml` | Synthetic (pre-existing) | Full PAN-OS XML config; has vsys1, 2 IPsec tunnels, GlobalProtect SSL VPN, 4 security rules |

### pfSense (`pfsense/`)

- **Searched**: `glennake/DirectFire_Converter` (no pfSense configs found)
- **Status**: Only pre-existing synthetic fixture available

| File | Source | Notable Characteristics |
|------|--------|------------------------|
| `sample_config.xml` | Synthetic (pre-existing) | pfSense 21.7.3 config.xml; OpenVPN server, IPsec phase1/phase2, 4 filter rules |

### SonicWall (`sonicwall/`)

- **Searched**: No public SonicWall export repositories found (vendor does not publish samples)
- **Status**: Only pre-existing synthetic fixture available

| File | Source | Notable Characteristics |
|------|--------|------------------------|
| `sample_export.xml` | Synthetic (pre-existing) | SonicOS 6.5.4 XML export; `<SonicwallConfig>` root; 2 IPsec VPN policies, SSL VPN, RADIUS |

### Sophos XG (`sophos_xg/`)

- **Searched**: No public Sophos XG backup repositories found
- **Status**: Only pre-existing synthetic fixture available

| File | Source | Notable Characteristics |
|------|--------|------------------------|
| `sample_backup.xml` | Synthetic (pre-existing) | SFOS 18.5.3 XML backup; `<Configuration>` root; has SNMPv3, 2 IPsec tunnels |

---

## Repositories Surveyed

| Repository | Branch Tried | Files Found |
|-----------|-------------|-------------|
| `Cyblex-Consulting/fortigate-security-auditor` | main | Python scripts only, no config samples |
| `glennake/DirectFire_Converter` | master | FortiGate .conf, WatchGuard .xml (old schema), Cisco ASA pre-8.3 .txt |
| `PaloAltoNetworks/iron-skillet` | main | Repository not accessible (404) |
| `moshekaplan/palo_alto_firewall_analyzer` | main | PAN_CONFIG.cfg is an analyzer config file, not a firewall XML |
| `AlekzNet/Cisco-ASA-ACL-toolkit` | master | test.acl (ACL-only snippet, no full running-config) |

---

## Schema Notes

- The `directfire_watchguard.xml` uses the **old WatchGuard XML schema** (X-series appliances, pre-Fireware 11).
  The FireAudit WatchGuard parser targets the **Fireware 11+** schema (`<policy>` or `<profile>` root with
  `<setup>`, `<interface>`, `<policy-tag>`, `<logging>`, `<ntp-client>`, `<snmp>` sections).
  The old schema uses `<policy-list>`, `<interface-list>` and is not compatible.
- The `directfire_ciscoasa_pre83.conf` uses ASA pre-8.3 ACL syntax (IP/mask in access-list statements
  without `object` keyword). The parser handles this correctly.
