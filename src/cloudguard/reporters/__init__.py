"""Output formats. Each reporter turns a ScanResult into a string."""

from __future__ import annotations

from collections.abc import Callable

from cloudguard.engine import ScanResult

from .console import render_console
from .json_report import render_json
from .sarif import render_sarif

Reporter = Callable[[ScanResult], str]

REPORTERS: dict[str, Reporter] = {
    "console": render_console,
    "json": render_json,
    "sarif": render_sarif,
}

__all__ = ["REPORTERS", "render_console", "render_json", "render_sarif"]
