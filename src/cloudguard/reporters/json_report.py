"""Machine-readable JSON report."""

from __future__ import annotations

import json

from cloudguard import __version__
from cloudguard.engine import ScanResult


def render_json(result: ScanResult) -> str:
    counts = result.count_by_severity()
    payload = {
        "tool": {"name": "cloudguard", "version": __version__},
        "provider": result.provider,
        "scope": result.scope,
        "checks_run": result.checks_run,
        "summary": {str(sev): n for sev, n in counts.items()},
        "findings": [f.to_dict() for f in result.findings],
        "errors": result.errors,
        "warnings": result.warnings,
    }
    return json.dumps(payload, indent=2) + "\n"
