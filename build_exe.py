#!/usr/bin/env python3
"""Build FireAudit as a standalone Windows executable using PyInstaller.

Usage:
    python build_exe.py

Output: dist/fireaudit.exe
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent
RULES_DIR = ROOT / "rules"
SCHEMA_DIR = ROOT / "fireaudit" / "schemas"


def main() -> None:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller not found. Install it with:  pip install pyinstaller")
        sys.exit(1)

    # Collect --add-data entries for rules (all yaml files) and schema
    add_data: list[str] = []

    # Bundle the entire rules/ directory tree
    for yaml_file in RULES_DIR.rglob("*.yaml"):
        rel_dir = yaml_file.parent.relative_to(ROOT)
        add_data += ["--add-data", f"{yaml_file};{rel_dir}"]

    # Bundle the IR JSON schema
    for json_file in SCHEMA_DIR.glob("*.json"):
        rel_dir = json_file.parent.relative_to(ROOT)
        add_data += ["--add-data", f"{json_file};fireaudit/schemas"]

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", "fireaudit",
        "--console",
        "--clean",
        "--noconfirm",
        # Hidden imports that PyInstaller may miss
        "--hidden-import", "fireaudit.parsers.fortigate",
        "--hidden-import", "fireaudit.parsers.paloalto",
        "--hidden-import", "fireaudit.parsers.cisco_asa",
        "--hidden-import", "fireaudit.parsers.pfsense",
        "--hidden-import", "fireaudit.parsers.sonicwall",
        "--hidden-import", "fireaudit.parsers.sophos_xg",
        "--hidden-import", "fireaudit.parsers.watchguard",
        "--hidden-import", "questionary",
        "--hidden-import", "prompt_toolkit",
        *add_data,
        # Entry point
        str(ROOT / "fireaudit_main.py"),
    ]

    print("Building fireaudit.exe ...")
    print(f"  Rules bundled: {len(list(RULES_DIR.rglob('*.yaml')))} yaml files")
    print()

    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode != 0:
        print("\nBuild FAILED.")
        sys.exit(1)

    exe = ROOT / "dist" / "fireaudit.exe"
    if exe.exists():
        size_mb = exe.stat().st_size / 1_048_576
        print(f"\nBuild succeeded: {exe}  ({size_mb:.1f} MB)")
        print("\nTest it with:  dist\\fireaudit.exe wizard")
    else:
        print("\nBuild completed but exe not found at expected path.")


if __name__ == "__main__":
    main()
