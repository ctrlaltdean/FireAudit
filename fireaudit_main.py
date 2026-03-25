"""PyInstaller entry-point for the standalone fireaudit executable.

This shim is needed so PyInstaller can locate the __main__ module for the
--onefile build. The actual CLI logic lives in fireaudit.cli.
"""
import sys
from pathlib import Path

# When running from a PyInstaller bundle, _MEIPASS is the temp directory where
# data files are extracted. We need the rules/ directory to be resolvable.
if getattr(sys, "frozen", False):
    _bundle_dir = Path(sys._MEIPASS)  # type: ignore[attr-defined]
    # Make the bundle dir available so RuleLoader default path resolves
    import os
    os.environ.setdefault("FIREAUDIT_RULES_DIR", str(_bundle_dir / "rules"))

from fireaudit.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
