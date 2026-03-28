#!/usr/bin/env python3
"""Build FireAudit as a standalone single-file binary using PyInstaller.

Works on Windows, macOS, and Linux.

Usage:
    python build_exe.py

Output:
    dist/fireaudit.exe   (Windows)
    dist/fireaudit       (macOS / Linux)
"""

import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent
RULES_DIR = ROOT / "rules"
SCHEMA_DIR = ROOT / "fireaudit" / "schemas"

# PyInstaller --add-data separator is ';' on Windows, ':' on Unix
_SEP = ";" if platform.system() == "Windows" else ":"


def main() -> None:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller not found. Install it with:  pip install pyinstaller")
        sys.exit(1)

    # Collect --add-data entries (rules + schema)
    add_data: list[str] = []

    for yaml_file in sorted(RULES_DIR.rglob("*.yaml")):
        rel_dir = yaml_file.parent.relative_to(ROOT)
        add_data += ["--add-data", f"{yaml_file}{_SEP}{rel_dir}"]

    for json_file in sorted(SCHEMA_DIR.glob("*.json")):
        add_data += ["--add-data", f"{json_file}{_SEP}fireaudit/schemas"]

    binary_name = "fireaudit"  # PyInstaller adds .exe automatically on Windows

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", binary_name,
        "--console",
        "--clean",
        "--noconfirm",
        # Ensure all vendor parsers are included (dynamic import via VENDOR_PARSERS dict)
        "--hidden-import", "fireaudit.parsers.fortigate",
        "--hidden-import", "fireaudit.parsers.paloalto",
        "--hidden-import", "fireaudit.parsers.cisco_asa",
        "--hidden-import", "fireaudit.parsers.cisco_ftd",
        "--hidden-import", "fireaudit.parsers.pfsense",
        "--hidden-import", "fireaudit.parsers.sonicwall",
        "--hidden-import", "fireaudit.parsers.sophos_xg",
        "--hidden-import", "fireaudit.parsers.watchguard",
        "--hidden-import", "fireaudit.parsers.checkpoint",
        "--hidden-import", "fireaudit.parsers.juniper_srx",
        "--hidden-import", "fireaudit.updater",
        "--hidden-import", "questionary",
        "--hidden-import", "prompt_toolkit",
        *add_data,
        str(ROOT / "fireaudit_main.py"),
    ]

    rule_count = len(list(RULES_DIR.rglob("*.yaml")))
    print(f"Building fireaudit binary ({platform.system()} / {platform.machine()})…")
    print(f"  Rules bundled : {rule_count} yaml files")
    print(f"  Add-data sep  : '{_SEP}'")
    print()

    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode != 0:
        print("\nBuild FAILED.")
        sys.exit(1)

    # Find the output binary
    exe_win = ROOT / "dist" / "fireaudit.exe"
    exe_unix = ROOT / "dist" / "fireaudit"
    exe = exe_win if exe_win.exists() else exe_unix

    if exe.exists():
        size_mb = exe.stat().st_size / 1_048_576
        print(f"\nBuild succeeded: {exe}  ({size_mb:.1f} MB)")
        if platform.system() == "Windows":
            print("Test:  dist\\fireaudit.exe wizard")
        else:
            print("Test:  ./dist/fireaudit wizard")
    else:
        print("\nBuild completed — binary not found at expected path.")


if __name__ == "__main__":
    main()
