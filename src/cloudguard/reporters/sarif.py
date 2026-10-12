"""SARIF 2.1.0 report.

Findings from Terraform point at the real source file and line. Findings from a live
cloud account have no file, so each result carries a synthetic ``physicalLocation`` (a path
derived from the resource ID, line 1). Both also carry a ``logicalLocation`` with the
resource ID.
"""

from __future__ import annotations

import hashlib
import json

from cloudguard import __version__
from cloudguard.engine import ScanResult
from cloudguard.models import Severity
from cloudguard.registry import all_checks

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub maps numeric "security-severity" (CVSS-like, 0-10) to its severity labels.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def _rule(meta) -> dict:
    tags = ["security", *(f"CIS-{c}" for c in meta.cis), *meta.mitre]
    return {
        "id": meta.id,
        "name": meta.title,
        "shortDescription": {"text": meta.title},
        "fullDescription": {"text": meta.description},
        "help": {"text": meta.remediation or meta.description},
        "defaultConfiguration": {"level": _LEVEL[meta.severity]},
        "properties": {
            "tags": tags,
            "security-severity": _SECURITY_SEVERITY[meta.severity],
        },
    }


def _artifact_path(provider: str, scope: str, resource_id: str) -> str:
    cleaned = resource_id.replace(":", "/").strip("/") or "unknown"
    return f"cloud/{provider}/{scope or 'default'}/{cleaned}"


def render_sarif(result: ScanResult) -> str:
    providers = set(result.provider.split("+"))
    rules = [_rule(c.meta) for c in all_checks() if c.meta.provider in providers]
    rule_index = {rule["id"]: i for i, rule in enumerate(rules)}

    results = []
    for f in result.findings:
        fingerprint = hashlib.sha256(f"{f.check_id}|{f.resource_id}".encode()).hexdigest()
        if f.file:
            uri, start_line = f.file, f.line or 1
        else:
            uri, start_line = _artifact_path(f.provider, result.scope, f.resource_id), 1
        results.append(
            {
                "ruleId": f.check_id,
                "ruleIndex": rule_index.get(f.check_id, -1),
                "level": _LEVEL[f.severity],
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": start_line},
                        },
                        "logicalLocations": [
                            {"name": f.resource_name, "fullyQualifiedName": f.resource_id}
                        ],
                    }
                ],
                "partialFingerprints": {"cloudguard/v1": fingerprint},
            }
        )

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CloudGuard",
                        "version": __version__,
                        "informationUri": "https://github.com/HamdiiOmar/cloudguard",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2) + "\n"
