"""Vendor-specific firewall configuration parsers."""

from fireaudit.parsers.base import BaseParser
from fireaudit.parsers.fortigate import FortiGateParser
from fireaudit.parsers.paloalto import PaloAltoParser
from fireaudit.parsers.pfsense import PfSenseParser, OPNsenseParser
from fireaudit.parsers.cisco_asa import CiscoASAParser, CiscoFTDParser
from fireaudit.parsers.sonicwall import SonicWallParser
from fireaudit.parsers.sophos_xg import SophosXGParser
from fireaudit.parsers.watchguard import WatchGuardParser
from fireaudit.parsers.checkpoint import CheckPointParser
from fireaudit.parsers.juniper_srx import JuniperSRXParser

VENDOR_PARSERS = {
    "fortigate": FortiGateParser,
    "paloalto": PaloAltoParser,
    "pfsense": PfSenseParser,
    "opnsense": OPNsenseParser,
    "cisco_asa": CiscoASAParser,
    "cisco_ftd": CiscoFTDParser,
    "sonicwall": SonicWallParser,
    "sophos_xg": SophosXGParser,
    "watchguard": WatchGuardParser,
    "checkpoint": CheckPointParser,
    "juniper_srx": JuniperSRXParser,
}


def get_parser(vendor: str) -> type[BaseParser]:
    vendor = vendor.lower().replace("-", "_").replace(" ", "_")
    if vendor not in VENDOR_PARSERS:
        raise ValueError(f"Unsupported vendor: '{vendor}'. Available: {list(VENDOR_PARSERS)}")
    return VENDOR_PARSERS[vendor]
