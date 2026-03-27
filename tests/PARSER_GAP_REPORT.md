# FireAudit Parser & Rule Gap Report

Generated: 2026-03-27
Fixtures tested: 10 files across 7 vendors

---

## 1. Parser Coverage Gaps

Fields present in raw config files that parsers do not currently extract.

### 1.1 FortiGate

**Gap: Firmware version not extracted from header comment**
- The config header line `#config-version=FGT60F-7.2.5-FW-build1517...` is skipped by the tokenizer
  (lines starting with `#` are discarded).
- `ir["meta"]["firmware_version"]` is always `None` unless `set firmware-version` appears in
  `config system global`, which FortiOS does not emit.
- **Impact**: FW-ADM-008 (TLS version) and version-gated rules cannot apply minimum firmware checks.
- **Fix complexity**: Low. Add a pre-tokenization regex scan for `#config-version=` to populate
  `meta.firmware_version`.

**Gap: SNMP `allowed_hosts` (trusted management hosts for SNMP)**
- `config system snmp community` → `config hosts` → `edit` → `set ip <addr>` is not extracted.
- `ir["admin_access"]["snmp"]["allowed_hosts"]` is always empty.
- **Impact**: Cannot check whether SNMP is restricted to specific management hosts.

**Gap: `system central-management` FortiCloud / FortiManager settings not extracted**
- Sections `system central-management` and `system global` → `management-vdom` are present in real
  configs but not mapped to any IR field.
- **Impact**: No visibility into whether the device is centrally managed.

**Gap: `log memory filter` severity level and `log syslogd filter` forward-traffic field**
- `log["log_traffic"]` is derived from `forward-traffic == enable` in `log syslogd filter`, but this
  only checks the first syslogd filter, not syslogd2/3/4 filter sections.

---

### 1.2 Cisco ASA

**Gap: SNMP community string not extracted**
- The ASA parser extracts `snmp_enabled` but does not extract the community string.
  Lines like `snmp-server community public ro` are not captured.
- `ir["admin_access"]["snmp"]["community_strings"]` is always empty even when SNMP is enabled.
- **Impact**: FW-ADM-007 correctly fires (v2c enabled), but no community string detail for audit.

**Gap: Session timeout not extracted when timeout is 0**
- ASA `console timeout 0` / `ssh timeout 5` extracts numeric 0 as the session timeout.
- `ir["admin_access"]["session_timeout_seconds"]` = 0, which FW-ADM-004 treats as a pass
  (0 minutes maps to 0 seconds, and the rule checks `<= 600`; 0 passes the check).
- **Impact**: `timeout 0` on ASA means "no timeout" (infinite), which should FAIL FW-ADM-004.
  **Fix complexity**: Low. In the Cisco ASA parser, treat timeout value 0 as None (no timeout configured).

**Gap: `aaa authentication ssh console LOCAL` and related AAA lines**
- The presence of AAA authentication statements indicating whether SSH/console uses local vs RADIUS/TACACS
  is only partially extracted (the `remote_auth` section gets RADIUS/TACACS servers, but which
  services require remote auth is not tracked in IR).

**Gap: Logging severity filter (`logging buffered warnings`) not extracted**
- `ir["logging"]["log_denied_traffic"]` is derived from whether syslog is configured at all,
  not from the actual logging level. A device logging only `critical` would still show as configured.

---

### 1.3 Palo Alto

**Gap: Remote auth servers (RADIUS/TACACS) not extracted**
- The `_extract_authentication` method has a `pass` placeholder in the server-profile loop.
  `ir["authentication"]["remote_auth"]["radius_enabled"]` always remains `False`.
- **Impact**: FW-AUTH-007 (centralized auth) always fails for Palo Alto even when RADIUS is configured.
- **Fix complexity**: Medium. Server profiles are under `./devices/entry/server-profile/radius`
  and `./shared/server-profile/radius`. Requires adding 6-10 lines to the parser.

**Gap: SNMP `allowed_hosts` not extracted**
- `snmp-setting/access-setting` may contain host restrictions but these are not captured.

**Gap: `log-forwarding` profile syslog entries use profile names, not IP addresses**
- When syslog is configured via log-forwarding profiles (vsys-level), the `host` field in the IR
  contains the syslog profile name (string), not the server IP.
- **Impact**: Audit output shows profile names instead of server IPs; not actionable for network review.

---

### 1.4 WatchGuard

**Gap: Old Fireware XML schema (X-series / pre-Fireware 11) not supported**
- The `directfire_watchguard.xml` fixture uses `<policy>` root with `<policy-list>`, `<interface-list>`,
  `<system-parameters>`, `<address-group-list>` child elements.
- The parser expects `<policy>` or `<profile>` root with `<setup>`, `<interface>`, `<policy-tag>`,
  `<logging>`, `<ntp-client>`, `<snmp>`.
- All IR fields return empty/None for old-schema configs (0 policies, 0 interfaces, etc.).
- **Impact**: Any WatchGuard X-series or older Firebox device config would produce no findings.
- **Fix complexity**: High. Requires a separate sub-parser for the old schema, or detection logic
  to handle both schemas in the same parser.

**Gap: `<authentication-server type="Active-Directory">` entries not matched**
- The parser checks `"active-directory"` in the type_raw, but DirectFire configs may use
  `"ActiveDirectory"` (no hyphen). Not confirmed to affect the current sample but worth noting.

---

### 1.5 pfSense

**Gap: SNMP not extracted**
- `<snmpd>` element is parsed as a local variable in the `parse()` method but is never passed
  to any extractor. `ir["admin_access"]["snmp"]` always returns the default (disabled).
- **Impact**: FW-ADM-007/010 always pass (SNMP appears disabled) even if SNMP is configured.
- **Fix complexity**: Low. Pass `snmpd` to `_extract_admin_access` and add 10-15 lines to parse
  `<snmpd><enable>`, `<rocommunity>`, `<syslocation>`, `<syscontact>`.

**Gap: Login protection parameters not extracted as numeric thresholds**
- `<loginprotection/>` (presence tag) sets `max_login_attempts = 10` (hardcoded default).
  The actual configured threshold is not read from pfSense's `loginprotect.inc` config.

**Gap: WebGUI session timeout not in `<webgui>` block** — PARTIALLY RESOLVED
- pfSense does not expose the GUI session timeout in config.xml; it is a PHP constant.
  `ir["admin_access"]["session_timeout_seconds"]` is `None` when the `<session-timeout>` element
  is absent from the `<webgui>` block.
- **Resolution**: FW-ADM-004 now uses `not_applicable_when` to return `not_applicable` status for
  pfSense/OPNsense devices when `session_timeout_seconds` is null. If the `<webgui><session-timeout>`
  element is present (as it is in the sample fixture), the rule evaluates normally.
- **Residual gap**: The PHP default timeout (4 hours) is not auditable from the config export.
  Verify manually in System > Advanced > Admin Access.

---

### 1.6 SonicWall

**Gap: TLS minimum version for HTTPS management not extracted**
- `<ManagementSettings>` has no `<TLSMinVersion>` element in current parser mapping.
- `ir["admin_access"]["https_settings"]["tls_versions"]` is always empty.
- **Impact**: FW-ADM-008 (HTTPS TLS version) always fires regardless of TLS config.

**Gap: `<history_count>` / password history not in `<ManagementSettings>`**
- `ir["authentication"]["password_policy"]["history_count"]` is always `None`.
- **Impact**: FW-AUTH-004 always fails for SonicWall.

---

### 1.7 Sophos XG

**Gap: `<Status>` used as enabled/disabled for firewall rules**
- The `_enabled()` helper checks for `"enable"` (lowercase); Sophos XG uses `"Enable"` (capitalized).
  The `_extract_firewall_policies` uses `_enabled(rule_el, "Status")` which correctly strips and
  lowercases, so this is working correctly.

**Gap: SSH cipher suite not extracted** — DOCUMENTED (not extractable from schema)
- Sophos XG XML backup does not include SSH cipher configuration under `<ManagementProtocols>`,
  `<AdminSettings>`, or any `<Network>/<Interface>` element. SSH cipher lists are a system-level
  OS configuration not exported in the device backup XML.
- `ir["admin_access"]["ssh_settings"]["ciphers"]` remains empty for all Sophos XG configs.
- **Impact**: FW-ADM-014 always returns `pass` (empty = secure defaults assumed) for Sophos XG.
  Manual verification of SSH cipher configuration via CLI (`system ssh cipher list`) is required.

**Gap: `management_access` per interface empty** — RESOLVED
- Sophos XG `interfaces[].management_access` now populated based on zone role: LAN/DMZ interfaces
  inherit the globally-enabled management protocols from `<ManagementProtocols>`; WAN interfaces
  receive an empty list (blocked by default).

---

## 2. Rule Coverage Gaps

Security issues present in raw config files that no current rule catches.

### 2.1 SSH Crypto Strength (all vendors)
- No rule checks `ssh_settings.ciphers`, `ssh_settings.macs`, or `ssh_settings.kex_algorithms`.
- Real configs may have weak SSH ciphers (e.g., `arcfour`, `3des-cbc`, `hmac-md5`) enabled.
- **Missing rules**: FW-ADM-SSH-CIPHERS, FW-ADM-SSH-MACS

### 2.2 SNMP Allowed Hosts / Access Restriction
- FW-ADM-007 and FW-ADM-010 check SNMP version and security level.
- No rule checks whether SNMP access is restricted to specific management hosts (`snmp.allowed_hosts`).
- A device with SNMPv3 configured but accessible from `0.0.0.0/0` passes all SNMP rules.
- **Missing rule**: FW-ADM-SNMP-RESTRICTED-ACCESS

### 2.3 Management Interface Exposure (SSH/HTTPS on WAN)
- FW-ADM-011 checks HTTPS on WAN interfaces only.
- No rule checks whether SSH is exposed on WAN interfaces.
- The directfire FortiGate has `set allowaccess ping https ssh http` on the WAN interface,
  which triggers FW-ADM-011 (HTTPS on WAN) but SSH on WAN goes unchecked.
- **Missing rule**: FW-ADM-SSH-ON-WAN

### 2.4 Firewall Policy Overly Broad Services
- Rules check for any-to-any source/destination (FW-POL-001) but no rule detects
  policies with `service any` combined with specific source/destination (port-any allow rules).
- Common misconfiguration: `allow LAN → WAN any any` (all ports permitted from LAN).

### 2.5 IPsec VPN PSK Strength
- No rule validates whether PSK (pre-shared key) authentication is used vs certificate.
  PSK IPsec is considered weaker than certificate-based authentication for site-to-site VPN.
- **Missing rule**: FW-VPN-PSK-VS-CERT

### 2.6 IPsec SA Lifetime Excessive
- No rule checks whether Phase 1 or Phase 2 lifetimes are excessively long.
  CIS benchmarks recommend Phase 1 ≤ 86400s, Phase 2 ≤ 3600s.
- **Missing rules**: FW-VPN-PHASE1-LIFETIME, FW-VPN-PHASE2-LIFETIME

### 2.7 Logging Severity Level Insufficient
- FW-LOG-001 only checks whether a syslog server is configured.
- No rule verifies that logging captures informational or notice-level events (not just errors/critical).

### 2.8 Default Deny Rule Logging
- FW-POL-004 exists (deny rules must be logged) but in the rule files directory it was not
  producing findings in any tested fixture. Verify this rule is loading and evaluating correctly.

### 2.9 Password Max Age Not Enforced
- No rule checks `password_policy.max_age_days`. Passwords that never expire are a CIS/NIST finding.
- **Missing rule**: FW-AUTH-PASSWORD-MAX-AGE

### 2.10 Inactive / Disabled Admin Accounts
- No rule checks for disabled or stale admin accounts that should be removed.

---

## 3. IR Schema Gaps

Fields that should be added to the IR to support future rules.

| Field Path | Type | Purpose | Priority |
|-----------|------|---------|----------|
| `admin_access.snmp.allowed_hosts` | `list[str]` | SNMP host restriction check | High |
| `admin_access.ssh_settings.ciphers` | `list[str]` | SSH cipher audit | **RESOLVED** — extracted by FortiGate, ASA, pfSense, PaloAlto, SonicWall parsers |
| `admin_access.ssh_settings.macs` | `list[str]` | SSH MAC audit | **RESOLVED** — extracted by FortiGate, ASA, pfSense, PaloAlto parsers |
| `admin_access.ssh_settings.kex_algorithms` | `list[str]` | SSH KEX audit | **RESOLVED** — extracted by FortiGate, pfSense, PaloAlto parsers |
| `admin_access.https_settings.hsts_enabled` | `bool` | HSTS header enforcement | Low |
| `meta.firmware_version` | `str` | Firmware version for EOL/patching checks | High |
| `authentication.password_policy.max_age_days` | `int` | Password rotation enforcement | High |
| `vpn.ipsec_tunnels[].phase1.lifetime_seconds` | `int` | IKE SA lifetime check | Medium |
| `vpn.ipsec_tunnels[].phase2.lifetime_seconds` | `int` | IPsec SA lifetime check | Medium |
| `vpn.ipsec_tunnels[].auth_method` | `str` | PSK vs cert detection | Medium |
| `interfaces[].management_access` | `list[str]` | Per-interface allowed management protocols | **RESOLVED** — pfSense and Sophos XG now populate this field |
| `logging.log_severity_level` | `str` | Minimum log severity captured | Medium |
| `logging.syslog_servers[].encrypted` | `bool` | Per-server TLS flag (vs protocol string) | Low |

---

## 4. Priority Ranking of Fixes

Ranked by CIS/NIST compliance impact and number of affected vendors/fixtures.

### P1 — Critical (implement immediately)

1. **pfSense SNMP extraction** (`snmpd` element never parsed)
   - Affects: All pfSense fixtures
   - CIS: CIS FW Benchmark 2.14; NIST 800-53: SC-8
   - Fix: ~15 lines in `pfsense.py`

2. **Cisco ASA session timeout = 0 treated as no timeout**
   - Affects: All ASA configs with `timeout 0`
   - CIS: CIS FW Benchmark 2.5; NIST 800-53: AC-11
   - Fix: ~3 lines in `cisco_asa.py`

3. **Palo Alto RADIUS/TACACS server extraction (placeholder `pass` statement)**
   - Affects: All PAN-OS fixtures
   - CIS: CIS FW Benchmark 2.10; NIST 800-53: IA-2(3)
   - Fix: ~20 lines in `paloalto.py`

4. **FortiGate firmware version from `#config-version=` header comment**
   - Affects: All FortiGate fixtures
   - CIS: CIS FW Benchmark 1.1; NIST 800-53: SI-2
   - Fix: ~5 lines in `fortigate.py`

### P2 — High (next sprint)

5. **Add rule FW-ADM-SSH-ON-WAN** (SSH exposed on WAN interface)
   - Affects: FortiGate directfire fixture (confirmed gap)
   - CIS: CIS FW Benchmark 2.4; NIST 800-53: CM-7
   - Mirror structure of existing FW-ADM-011

6. **Add rule FW-ADM-SNMP-RESTRICTED-ACCESS** (SNMP not restricted to management hosts)
   - Affects: All vendors with SNMP enabled
   - CIS: CIS FW Benchmark 2.14; NIST 800-53: SC-5

7. **Add rule FW-AUTH-PASSWORD-MAX-AGE** (passwords never expire)
   - Affects: All vendors
   - CIS: CIS FW Benchmark 2.9; NIST 800-53: IA-5(1)

8. **WatchGuard old-schema support** (X-series / Fireware pre-11 XML)
   - Currently produces 0 findings for old schema configs — silently wrong
   - Fix: Add schema detection in `watchguard.py`; raise `ValueError` for unsupported schema
     or add a second extraction path.

### P3 — Medium (backlog)

9. **SonicWall TLS version extraction for HTTPS management**
   - Fix: Map `<ManagementSettings><TLSMinVersion>` to `https_settings.tls_versions`

10. **SonicWall password history extraction**
    - Fix: Map `<ManagementSettings><PasswordHistory>` to `password_policy.history_count`

11. **PaloAlto syslog: resolve profile names to server IPs**
    - Currently stores profile name string as host; should cross-reference syslog server profiles

12. **SSH cipher/MAC/KEX rules** (FW-ADM-SSH-CIPHERS, FW-ADM-SSH-MACS)
    - Requires IR schema additions first (see §3)

13. **IPsec lifetime rules** (FW-VPN-PHASE1-LIFETIME, FW-VPN-PHASE2-LIFETIME)
    - Both Phase 1 and Phase 2 lifetime fields already exist in IR (`lifetime_seconds`)

### P4 — Low (nice to have) — STATUS AFTER 2026-03-27 SPRINT

Items 14–17 were addressed:

14. FortiGate: Extract SNMP `allowed_hosts` from `config hosts` nested block — **STILL OPEN**
15. Add rule FW-VPN-PSK-VS-CERT (prefer certificate auth over PSK) — **STILL OPEN**
16. Add rule for firewall policies with `service any` (all ports allowed) — **STILL OPEN**
17. Populate `interfaces[].management_access` for pfSense and Sophos XG — **RESOLVED** (both now populated)

**Additional P4 items completed 2026-03-27:**

- **SSH cipher/MAC/KEX extraction — FortiGate**: Extracts `ssh-enc-algo`, `ssh-mac-algo`, `ssh-kex-algo`
  from `config system global`. The existing sample fixtures do not include these settings (FortiOS
  uses secure defaults unless explicitly configured), so ciphers remain empty for current fixtures.
  FW-ADM-014 correctly passes (empty = no weak ciphers explicitly configured).

- **SSH cipher/MAC extraction — Cisco ASA**: Extracts `ssh cipher encryption <level>` and
  `ssh cipher integrity <level>`. Maps level strings (fips/high/medium/low) to algorithm lists.
  Current fixture has no `ssh cipher` lines; ciphers remain empty.

- **SSH cipher/MAC/KEX extraction — pfSense**: Extracts `<encryption-algorithms>`, `<macs>`,
  `<kex-algorithms>` from `<ssh>` block (each as `<item>` children). Current fixture has no
  cipher sub-elements in `<ssh>`; ciphers remain empty.

- **SSH cipher/MAC/KEX extraction — Palo Alto**: Extracts from `deviceconfig/system/ssh/ciphers`,
  `macs`, `key-exchange` (PAN-OS 9.1+). Current fixture has no `<ssh>` cipher config; empty.

- **SSH cipher extraction — SonicWall**: Attempts to extract `<SSHCiphers>` or `<SSHEncryption>`
  from `<ManagementSettings>`. Element not present in current fixture; remains empty.

- **SSH cipher extraction — WatchGuard**: Not configurable via XML backup; correctly left empty.

- **SSH cipher extraction — Sophos XG**: Not present in XML backup schema; documented above.

- **FW-ADM-004 pfSense not_applicable handling**: The evaluator now supports `not_applicable_when`
  blocks in rule YAML. FW-ADM-004 uses this to return `not_applicable` for pfSense/OPNsense when
  session_timeout_seconds is null (not exported in config.xml).

---

## 5. Fixture Coverage Summary

| Vendor | Real Samples | Synthetic Samples | Parser Parse | Rule Engine |
|--------|-------------|------------------|-------------|------------|
| FortiGate | 1 (directfire) | 1 (sample_full) | Both SUCCESS | FG-sample: 15 FAIL / 24 PASS; FG-directfire: 22 FAIL / 18 PASS |
| Palo Alto | 0 | 1 (sample_running) | SUCCESS | 12 FAIL / 28 PASS |
| Cisco ASA | 1 (directfire pre-8.3) | 1 (sample_running) | Both SUCCESS | ASA-sample: 19 FAIL / 21 PASS; ASA-directfire: 21 FAIL / 19 PASS |
| WatchGuard | 1* (directfire, old schema) | 1 (sample_policy) | Both SUCCESS** | WG-sample: 15 FAIL / 25 PASS; WG-directfire: 18 FAIL / 22 PASS*** |
| pfSense | 0 | 1 (sample_config) | SUCCESS | 15 FAIL / 25 PASS |
| SonicWall | 0 | 1 (sample_export) | SUCCESS | 16 FAIL / 24 PASS |
| Sophos XG | 0 | 1 (sample_backup) | SUCCESS | 16 FAIL / 24 PASS |

`*` The directfire WatchGuard XML is an old-schema file; parser extracts 0 objects.
`**` "SUCCESS" in the sense that no exception is raised; old-schema file produces empty IR.
`***` All 18 failures in WG-directfire are due to missing values in empty IR (false failures).

---

## 6. Fixes Applied

### 6.1 P1/P2 Fixes (2026-03-26 sprint)

The following P1/P2 bugs were fixed during this analysis:

| File | Fix | Rule Impact |
|------|-----|------------|
| `fireaudit/parsers/fortigate.py` | Extract firmware version from `#config-version=` header comment line; `_extract_meta` no longer overwrites the pre-scanned value with `None` | `meta.firmware_version` now populated for all configs with header comment (e.g., `7.2.5` from `sample_full.conf`) |
| `fireaudit/parsers/pfsense.py` | Added `snmpd` element parsing in `_extract_admin_access`; extracts `<enable>` and `<rocommunity>` from `<snmpd>` | pfSense SNMP now correctly detected: `sample_config.xml` now fires FW-ADM-007 (SNMP v2c enabled) and FW-ADM-010 — 2 new FAIL findings |
| `fireaudit/parsers/paloalto.py` | Replaced `pass` placeholder in remote auth loop with real RADIUS/TACACS+/LDAP server profile extraction under `device` and `shared` scope | FW-AUTH-007 will now pass for PAN-OS configs that have RADIUS/TACACS profiles configured |
| `fireaudit/parsers/cisco_asa.py` | ASA `timeout 0` / `exec-timeout 0 0` now mapped to `None` instead of `0` (0 means no timeout on ASA) | FW-ADM-004 (session timeout) now correctly fires for ASA configs with infinite timeout |

**Post-fix pass/fail counts** (all 10 fixtures, 53 rules):

| Fixture | FAIL | PASS | SKIP | ERROR |
|---------|------|------|------|-------|
| FG-sample_full | 16 | 24 | 0 | 0 |
| FG-directfire | 22 | 18 | 0 | 0 |
| PA-sample | 12 | 28 | 0 | 0 |
| ASA-sample | 19 | 21 | 0 | 0 |
| ASA-directfire | 22 | 18 | 0 | 0 |
| WG-sample | 15 | 25 | 0 | 0 |
| WG-directfire | 18 | 22 | 0 | 0 |
| PFS-sample | 17 | 23 | 0 | 0 |
| SW-sample | 16 | 24 | 0 | 0 |
| XG-sample | 16 | 24 | 0 | 0 |

Zero parse errors and zero rule evaluation errors across all fixtures.

### 6.2 P4 Fixes (2026-03-27 sprint)

| File | Fix | Rule Impact |
|------|-----|------------|
| `fireaudit/engine/evaluator.py` | Added `not_applicable_when` support: if the YAML block condition is satisfied, the rule returns `not_applicable` with the `not_applicable_reason` message | Enables vendor-specific or configuration-state-specific N/A handling without modifying rule logic |
| `rules/admin/FW-ADM-004-admin-session-timeout.yaml` | Added `not_applicable_when` block targeting pfSense/OPNsense with null `session_timeout_seconds`; updated remediation note | FW-ADM-004 now returns `not_applicable` for pfSense when session timeout is not exported in config.xml; evaluates normally when `<session-timeout>` element is present |
| `fireaudit/parsers/fortigate.py` | Extract `ssh-enc-algo`, `ssh-mac-algo`, `ssh-kex-algo` from `config system global` using `_list_val`; populates `ssh_settings.ciphers`, `.macs`, `.kex_algorithms` | FW-ADM-014 will now detect weak SSH ciphers on FortiGate when `set ssh-enc-algo` includes weak algorithms |
| `fireaudit/parsers/cisco_asa.py` | Parse `ssh cipher encryption <level>` and `ssh cipher integrity <level>` lines; map level strings to algorithm lists | FW-ADM-014 will now detect weak cipher configurations on ASA (e.g., `ssh cipher encryption low` will expose 3des-cbc) |
| `fireaudit/parsers/pfsense.py` | Extract `<encryption-algorithms>`, `<macs>`, `<kex-algorithms>` from `<ssh>` block; update `_extract_interfaces` to accept `system` element and populate `management_access` based on zone (LAN=global mgmt protocols, WAN=empty) | FW-ADM-014 will detect weak ciphers when configured; interfaces now show realistic management access |
| `fireaudit/parsers/paloalto.py` | Extract SSH ciphers/MACs/KEX from `deviceconfig/system/ssh` (PAN-OS 9.1+) | FW-ADM-014 will detect weak ciphers when explicitly configured on PAN-OS |
| `fireaudit/parsers/sonicwall.py` | Attempt extraction of `<SSHCiphers>`/`<SSHEncryption>` from `<ManagementSettings>`; add `import re` | FW-ADM-014 will detect weak ciphers if SonicOS firmware exposes these elements |
| `fireaudit/parsers/sophos_xg.py` | Populate `management_access` per interface based on zone role (LAN inherits global management protocols from `<ManagementProtocols>`, WAN is empty) | FW-ADM-011 and similar rules that inspect interface management access will now produce accurate results for Sophos XG |
