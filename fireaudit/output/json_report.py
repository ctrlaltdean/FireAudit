"""JSON report output."""

from __future__ import annotations

import json
from pathlib import Path


def render_json(report: dict, output_path: str | Path | None = None, indent: int = 2) -> str:
    """Serialize report dict to JSON. Returns JSON string."""
    text = json.dumps(report, indent=indent, default=str)
    if output_path:
        Path(output_path).write_text(text, encoding="utf-8")
    return text
