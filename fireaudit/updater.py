"""FireAudit self-updater and rules updater.

Checks GitHub releases for:
  - New application versions  (fireaudit update check / fireaudit update apply)
  - New / updated rules        (fireaudit rules update)

All network calls use only the stdlib (urllib) — no extra dependencies.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import stat
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GITHUB_REPO = "ctrlaltdean/FireAudit"
GITHUB_API_LATEST = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
GITHUB_API_RELEASE = f"https://api.github.com/repos/{GITHUB_REPO}/releases/tags/{{tag}}"

# Per-user directory for locally updated rules and settings
USER_DATA_DIR = Path.home() / ".fireaudit"
USER_RULES_DIR = USER_DATA_DIR / "rules"


# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------

def current_version() -> str:
    from fireaudit import __version__
    return __version__


def _parse_version(tag: str) -> tuple[int, ...]:
    """Parse a version string like 'v1.2.3' or '1.2.3' into a comparable tuple."""
    return tuple(int(x) for x in tag.lstrip("v").split(".") if x.isdigit())


def is_newer(remote_tag: str, local_version: str | None = None) -> bool:
    """Return True if *remote_tag* is strictly newer than *local_version*."""
    local = local_version or current_version()
    try:
        return _parse_version(remote_tag) > _parse_version(local)
    except Exception:
        return remote_tag.lstrip("v") != local.lstrip("v")


# ---------------------------------------------------------------------------
# GitHub API
# ---------------------------------------------------------------------------

def _github_get(url: str) -> dict:
    """Perform a simple GET to the GitHub API and return parsed JSON."""
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": f"fireaudit/{current_version()}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"GitHub API error {exc.code}: {exc.reason}") from exc
    except Exception as exc:
        raise RuntimeError(f"Network error: {exc}") from exc


def fetch_latest_release() -> dict:
    """Return the latest release metadata dict from GitHub."""
    return _github_get(GITHUB_API_LATEST)


def check_for_update() -> Optional[dict]:
    """Return release info dict if a newer version exists, else None."""
    release = fetch_latest_release()
    if is_newer(release["tag_name"]):
        return release
    return None


# ---------------------------------------------------------------------------
# Platform asset name
# ---------------------------------------------------------------------------

def platform_asset_name() -> str:
    """Return the asset filename for the current OS/arch."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "windows":
        return "fireaudit-windows-x86_64.exe"
    elif system == "darwin":
        # Only arm64 is built via CI. Intel Macs run it under Rosetta 2.
        return "fireaudit-macos-arm64"
    else:
        # Linux and other Unix-likes
        return "fireaudit-linux-x86_64"


def _find_asset(release: dict, name: str) -> Optional[str]:
    """Return the download URL for an asset by name, or None."""
    for asset in release.get("assets", []):
        if asset["name"] == name:
            return asset["browser_download_url"]
    return None


# ---------------------------------------------------------------------------
# Download helper
# ---------------------------------------------------------------------------

def _download(url: str, dest: Path, progress_cb=None) -> None:
    """Download *url* to *dest*, calling *progress_cb(downloaded, total)* periodically."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": f"fireaudit/{current_version()}"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        chunk = 65536
        with dest.open("wb") as fh:
            while True:
                data = resp.read(chunk)
                if not data:
                    break
                fh.write(data)
                downloaded += len(data)
                if progress_cb:
                    progress_cb(downloaded, total)


# ---------------------------------------------------------------------------
# Binary self-update
# ---------------------------------------------------------------------------

def current_exe() -> Path:
    """Return the path to the currently running executable."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable)
    # Running as a regular Python script — return the script path
    return Path(sys.argv[0]).resolve()


def apply_binary_update(release: dict, progress_cb=None) -> str:
    """Download the new binary and replace the current executable.

    Returns a human-readable status message.

    On Windows the running exe cannot be overwritten directly; we rename the
    old one to `*.bak` and put the new one in its place.  The caller should
    inform the user to restart.
    """
    asset_name = platform_asset_name()
    download_url = _find_asset(release, asset_name)
    if not download_url:
        raise RuntimeError(
            f"No asset named '{asset_name}' found in release {release['tag_name']}. "
            "Check https://github.com/ctrlaltdean/FireAudit/releases for available binaries."
        )

    exe_path = current_exe()

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp) / asset_name
        _download(download_url, tmp_path, progress_cb=progress_cb)

        # Make executable on Unix
        if platform.system() != "Windows":
            tmp_path.chmod(tmp_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

        if platform.system() == "Windows":
            # Can't overwrite a running exe — rename old, move new into place
            backup = exe_path.with_suffix(".exe.bak")
            try:
                backup.unlink(missing_ok=True)
            except Exception:
                pass
            exe_path.rename(backup)
            shutil.move(str(tmp_path), str(exe_path))
            return (
                f"Updated to {release['tag_name']}. "
                f"Old binary saved as {backup.name}. "
                "Please restart FireAudit."
            )
        else:
            # Unix: replace directly
            shutil.move(str(tmp_path), str(exe_path))
            return f"Updated to {release['tag_name']}. Please restart FireAudit."


# ---------------------------------------------------------------------------
# Rules update
# ---------------------------------------------------------------------------

def apply_rules_update(release: dict, progress_cb=None) -> str:
    """Download rules.zip from *release* and extract to USER_RULES_DIR.

    Existing rule files are overwritten; rules not present in the archive are
    left untouched (so locally-added custom rules survive updates).

    Returns a human-readable status message.
    """
    download_url = _find_asset(release, "rules.zip")
    if not download_url:
        raise RuntimeError(
            f"No rules.zip asset found in release {release['tag_name']}."
        )

    USER_RULES_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        zip_path = Path(tmp) / "rules.zip"
        _download(download_url, zip_path, progress_cb=progress_cb)

        with zipfile.ZipFile(zip_path) as zf:
            # Extract only .yaml/.yml files, stripping a leading 'rules/' prefix
            extracted = 0
            for member in zf.namelist():
                if not (member.endswith(".yaml") or member.endswith(".yml")):
                    continue
                # Strip leading path component ('rules/admin/...' -> 'admin/...')
                parts = Path(member).parts
                if parts[0] == "rules":
                    parts = parts[1:]
                rel = Path(*parts) if parts else None
                if rel is None:
                    continue
                dest = USER_RULES_DIR / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, dest.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
                extracted += 1

    return (
        f"Rules updated to {release['tag_name']}: "
        f"{extracted} rule files written to {USER_RULES_DIR}"
    )


# ---------------------------------------------------------------------------
# Effective rules directory (used by CLI)
# ---------------------------------------------------------------------------

def effective_rules_dir(bundled_rules_dir: Path) -> Path:
    """Return the rules directory to use.

    Prefers the user rules dir (~/.fireaudit/rules/) if it exists and contains
    at least one rule file, falling back to the bundled directory.
    """
    if USER_RULES_DIR.exists() and any(USER_RULES_DIR.rglob("*.yaml")):
        return USER_RULES_DIR
    return bundled_rules_dir
