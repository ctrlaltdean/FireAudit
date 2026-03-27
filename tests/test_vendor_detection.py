"""Tests for vendor auto-detection."""

import pytest
from fireaudit.parsers.base import detect_vendor


# Minimal snippets that trigger each vendor's signature
_FORTIGATE = "#config-version=FGT60F-7.2.5-FW-build1517-230301:opmode=0:vdom=0\nconfig system global\n    set hostname FW-CORE-01\nend\n"
_FORTIGATE_NO_HEADER = "config system global\n    set hostname FW-BRANCH\n    set timezone 04\nend\n"
_PALOALTO = '<?xml version="1.0"?>\n<config version="10.1.0">\n  <devices>\n    <entry name="localhost.localdomain">\n'
_CISCO_ASA = "ASA Version 9.12(4)40\n!\nhostname FW-ASA-01\n"
_CISCO_ASDM = "ASDM Version 7.18(1)150\n"
_PFSENSE = '<?xml version="1.0"?>\n<pfsense>\n  <version>21.7</version>\n'
_PFSENSE_CAPS = '<?xml version="1.0"?>\n<pfSense>\n  <version>22.01</version>\n'
_OPNSENSE = '<?xml version="1.0"?>\n<opnsense>\n  <version>22.7</version>\n'
_SONICWALL = '<?xml version="1.0"?>\n<SonicwallSettings>\n  <DeviceName>NSA-3700</DeviceName>\n'
_SOPHOS_XG = '<?xml version="1.0"?>\n<Configuration firmware_appliancekey="SFM-XXXXXX">\n'
_WATCHGUARD = '<?xml version="1.0"?>\n<policy os-version="12.10.0.B692988">\n  <setup>\n    <name>Firebox-01</name>\n'
_WATCHGUARD_MARKER = '<?xml version="1.0"?>\n<policy>\n  WatchGuard Firebox configuration\n  <interface name="External">\n'
_UNKNOWN = "This is not a firewall config.\nSome random text.\n"


class TestDetectVendor:
    def test_fortigate_header(self):
        assert detect_vendor(_FORTIGATE) == "fortigate"

    def test_fortigate_no_header(self):
        assert detect_vendor(_FORTIGATE_NO_HEADER) == "fortigate"

    def test_paloalto(self):
        assert detect_vendor(_PALOALTO) == "paloalto"

    def test_cisco_asa(self):
        assert detect_vendor(_CISCO_ASA) == "cisco_asa"

    def test_cisco_asdm(self):
        assert detect_vendor(_CISCO_ASDM) == "cisco_asa"

    def test_pfsense_lowercase(self):
        assert detect_vendor(_PFSENSE) == "pfsense"

    def test_pfsense_mixed_case(self):
        assert detect_vendor(_PFSENSE_CAPS) == "pfsense"

    def test_opnsense(self):
        assert detect_vendor(_OPNSENSE) == "opnsense"

    def test_sonicwall(self):
        assert detect_vendor(_SONICWALL) == "sonicwall"

    def test_sophos_xg(self):
        assert detect_vendor(_SOPHOS_XG) == "sophos_xg"

    def test_watchguard_setup(self):
        assert detect_vendor(_WATCHGUARD) == "watchguard"

    def test_watchguard_marker(self):
        assert detect_vendor(_WATCHGUARD_MARKER) == "watchguard"

    def test_unknown_returns_none(self):
        assert detect_vendor(_UNKNOWN) is None

    def test_empty_returns_none(self):
        assert detect_vendor("") is None

    def test_only_first_4k_checked(self):
        """Detection should still work when signature is within first 4 KB."""
        padding = "x" * 100
        assert detect_vendor(padding + _FORTIGATE) == "fortigate"
