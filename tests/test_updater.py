"""Tests for pure (non-network) functions in fireaudit/updater.py."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from fireaudit.updater import (
    _parse_version,
    is_newer,
    current_version,
    platform_asset_name,
    _find_asset,
    effective_rules_dir,
    apply_rules_update,
)


# ---------------------------------------------------------------------------
# TestParseVersion
# ---------------------------------------------------------------------------

class TestParseVersion:
    def test_with_v_prefix(self):
        assert _parse_version("v1.2.3") == (1, 2, 3)

    def test_without_v_prefix(self):
        assert _parse_version("0.5.3") == (0, 5, 3)

    def test_two_part(self):
        assert _parse_version("2.0") == (2, 0)


# ---------------------------------------------------------------------------
# TestIsNewer
# ---------------------------------------------------------------------------

class TestIsNewer:
    def test_newer_patch(self):
        assert is_newer("v0.5.4", "0.5.3") is True

    def test_newer_minor(self):
        assert is_newer("v0.6.0", "0.5.3") is True

    def test_same_version(self):
        assert is_newer("v0.5.3", "0.5.3") is False

    def test_older_version(self):
        assert is_newer("v0.5.2", "0.5.3") is False

    def test_uses_current_if_no_local(self):
        with patch("fireaudit.updater.current_version", return_value="0.5.0"):
            assert is_newer("v0.6.0") is True


# ---------------------------------------------------------------------------
# TestCurrentVersion
# ---------------------------------------------------------------------------

class TestCurrentVersion:
    def test_returns_string(self):
        assert isinstance(current_version(), str)

    def test_contains_dots(self):
        assert "." in current_version()


# ---------------------------------------------------------------------------
# TestPlatformAssetName
# ---------------------------------------------------------------------------

class TestPlatformAssetName:
    def test_windows(self):
        with patch("platform.system", return_value="Windows"):
            name = platform_asset_name()
        assert name.endswith(".exe"), (
            f"Expected .exe extension on Windows, got: {name}"
        )

    def test_linux(self):
        with patch("platform.system", return_value="Linux"):
            name = platform_asset_name()
        assert "linux" in name.lower(), (
            f"Expected 'linux' in asset name on Linux, got: {name}"
        )

    def test_macos(self):
        with patch("platform.system", return_value="Darwin"):
            name = platform_asset_name()
        assert "macos" in name.lower(), (
            f"Expected 'macos' in asset name on Darwin, got: {name}"
        )


# ---------------------------------------------------------------------------
# TestFindAsset
# ---------------------------------------------------------------------------

class TestFindAsset:
    def test_found(self):
        release = {
            "assets": [
                {"name": "fireaudit.exe", "browser_download_url": "http://x"},
            ]
        }
        assert _find_asset(release, "fireaudit.exe") == "http://x"

    def test_not_found(self):
        assert _find_asset({"assets": []}, "fireaudit.exe") is None

    def test_wrong_name(self):
        release = {
            "assets": [
                {"name": "other.exe", "browser_download_url": "x"},
            ]
        }
        assert _find_asset(release, "fireaudit.exe") is None


# ---------------------------------------------------------------------------
# TestEffectiveRulesDir
# ---------------------------------------------------------------------------

class TestEffectiveRulesDir:
    def test_returns_bundled_when_user_dir_empty(self, tmp_path):
        bundled = tmp_path / "bundled_rules"
        bundled.mkdir()
        user_dir = tmp_path / "user_rules"
        # user_dir does not exist — should fall back to bundled
        with patch("fireaudit.updater.USER_RULES_DIR", user_dir):
            result = effective_rules_dir(bundled)
        assert result == bundled

    def test_returns_user_dir_when_populated(self, tmp_path):
        bundled = tmp_path / "bundled_rules"
        bundled.mkdir()
        user_dir = tmp_path / "user_rules"
        user_dir.mkdir()
        # Write a .yaml file so the user dir looks populated
        (user_dir / "test_rule.yaml").write_text(
            "rule_id: TEST\nname: Test\nseverity: info\nmatch: {}\n",
            encoding="utf-8",
        )
        with patch("fireaudit.updater.USER_RULES_DIR", user_dir):
            result = effective_rules_dir(bundled)
        assert result == user_dir


# ---------------------------------------------------------------------------
# TestApplyRulesUpdate
# ---------------------------------------------------------------------------

class TestApplyRulesUpdate:
    def test_no_rules_zip_asset(self):
        release = {
            "tag_name": "v0.5.0",
            "assets": [],
        }
        with pytest.raises(RuntimeError, match="rules.zip"):
            apply_rules_update(release)

    def test_extracts_yaml_files(self, tmp_path):
        # Build an in-memory zip that contains one yaml rule file
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("rules/admin/test.yaml", "rule_id: TEST\nname: Test Rule\n")
        buf.seek(0)
        zip_bytes = buf.read()

        def fake_download(url, dest, progress_cb=None):
            dest.write_bytes(zip_bytes)

        release = {
            "tag_name": "v0.5.1",
            "assets": [
                {
                    "name": "rules.zip",
                    "browser_download_url": "http://example.com/rules.zip",
                }
            ],
        }

        user_dir = tmp_path / "rules"

        with patch("fireaudit.updater.USER_RULES_DIR", user_dir), \
             patch("fireaudit.updater._download", side_effect=fake_download):
            msg = apply_rules_update(release)

        # The extracted yaml file should appear under USER_RULES_DIR/admin/test.yaml
        extracted = user_dir / "admin" / "test.yaml"
        assert extracted.exists(), (
            f"Expected extracted yaml at {extracted}"
        )
        assert "TEST" in extracted.read_text(encoding="utf-8")
        assert "v0.5.1" in msg
