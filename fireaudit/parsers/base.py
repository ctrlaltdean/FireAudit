"""Abstract base class for all vendor parsers."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path


class BaseParser(ABC):
    """Base class that all vendor parsers must implement.

    Parsers convert raw vendor config files into the normalized IR dict.
    """

    vendor: str = ""

    def __init__(self, source_file: str | Path | None = None) -> None:
        self.source_file = str(source_file) if source_file else None

    @abstractmethod
    def parse(self, content: str) -> dict:
        """Parse raw configuration text and return a normalized IR dict."""

    def parse_file(self, path: str | Path) -> dict:
        path = Path(path)
        content = path.read_text(encoding="utf-8", errors="replace")
        self.source_file = str(path)
        return self.parse(content)

    def _base_ir(self) -> dict:
        """Return a skeleton IR with all top-level keys populated with safe defaults."""
        return {
            "meta": {
                "vendor": self.vendor,
                "hostname": None,
                "model": None,
                "firmware_version": None,
                "serial_number": None,
                "config_timestamp": None,
                "source_file": self.source_file,
            },
            "admin_access": {
                "management_protocols": [],
                "ssh_settings": {
                    "enabled": False,
                    "version": None,
                    "ciphers": [],
                    "macs": [],
                    "kex_algorithms": [],
                    "idle_timeout_seconds": None,
                },
                "https_settings": {
                    "enabled": False,
                    "tls_versions": [],
                    "ciphers": [],
                    "hsts_enabled": None,
                },
                "snmp": {
                    "enabled": False,
                    "version": None,
                    "community_strings": [],
                    "allowed_hosts": [],
                },
                "session_timeout_seconds": None,
                "max_login_attempts": None,
                "lockout_duration_seconds": None,
                "trusted_hosts": [],
                "banner": None,
                "banner_enabled": None,
            },
            "authentication": {
                "local_users": [],
                "password_policy": {
                    "min_length": None,
                    "require_uppercase": None,
                    "require_lowercase": None,
                    "require_numbers": None,
                    "require_special": None,
                    "max_age_days": None,
                    "min_age_days": None,
                    "history_count": None,
                    "lockout_threshold": None,
                },
                "remote_auth": {
                    "radius_enabled": False,
                    "tacacs_enabled": False,
                    "ldap_enabled": False,
                    "servers": [],
                },
                "mfa_enabled_globally": None,
                "default_admin_account_exists": None,
                "default_admin_renamed": None,
            },
            "logging": {
                "syslog_servers": [],
                "local_logging_enabled": None,
                "log_traffic": None,
                "log_denied_traffic": None,
                "log_allowed_traffic": None,
                "log_authentication": None,
                "log_admin_actions": None,
                "log_system_events": None,
                "log_vpn": None,
                "log_retention_days": None,
                "ntp_servers": [],
                "ntp_enabled": None,
            },
            "vpn": {
                "ipsec_tunnels": [],
                "ssl_vpn": {
                    "enabled": False,
                    "tls_versions": [],
                    "ciphers": [],
                    "mfa_required": None,
                    "split_tunneling": None,
                    "client_certificate_required": None,
                },
            },
            "firewall_policies": [],
            "interfaces": [],
            "network_objects": {
                "address_objects": [],
                "service_objects": [],
            },
        }

    def to_json(self, ir: dict, indent: int = 2) -> str:
        return json.dumps(ir, indent=indent, default=str)
