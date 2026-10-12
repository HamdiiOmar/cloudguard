"""Scan engine: runs registered checks against an Inventory."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from .models import Finding, Inventory, Severity
from .registry import all_checks, load_provider


@dataclass
class ScanResult:
    provider: str
    scope: str
    findings: list[Finding] = field(default_factory=list)
    checks_run: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def count_by_severity(self) -> dict[Severity, int]:
        counts = Counter(f.severity for f in self.findings)
        return {sev: counts.get(sev, 0) for sev in sorted(Severity, reverse=True)}

    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)


def _source_index(inventory: Inventory) -> dict[str, dict]:
    """Map resource id/name to its ``_source`` (file and line), for resources that have one."""
    index: dict[str, dict] = {}
    for items in inventory.resources.values():
        for item in items:
            source = item.get("_source")
            key = item.get("id") or item.get("name")
            if source and key:
                index[key] = source
    return index


def merge_results(results: list[ScanResult]) -> ScanResult:
    """Combine results from several inventories (for example Terraform with AWS and Azure)."""
    if len(results) == 1:
        return results[0]
    merged = ScanResult(
        provider="+".join(sorted({r.provider for r in results})),
        scope="; ".join(dict.fromkeys(r.scope for r in results if r.scope)),
    )
    for result in results:
        merged.findings.extend(result.findings)
        merged.checks_run += result.checks_run
        merged.errors.extend(result.errors)
        merged.warnings.extend(result.warnings)
    merged.findings.sort(key=lambda f: (-int(f.severity), f.check_id, f.resource_name))
    return merged


def run_scan(
    inventory: Inventory,
    *,
    min_severity: Severity = Severity.INFO,
    only: Iterable[str] | None = None,
    skip: Iterable[str] | None = None,
) -> ScanResult:
    """Run every applicable check. A check that raises is recorded, not fatal."""
    load_provider(inventory.provider)
    only_set = {c.upper() for c in only} if only else None
    skip_set = {c.upper() for c in skip} if skip else set()

    result = ScanResult(
        provider=inventory.provider,
        scope=inventory.scope,
        warnings=list(inventory.warnings),
    )
    sources = _source_index(inventory)

    for registered in all_checks(inventory.provider):
        meta = registered.meta
        if only_set is not None and meta.id.upper() not in only_set:
            continue
        if meta.id.upper() in skip_set:
            continue

        result.checks_run += 1
        try:
            hits = list(registered.fn(inventory))
        except Exception as exc:  # noqa: BLE001 - one broken check must not hide the others
            result.errors.append(f"{meta.id}: {type(exc).__name__}: {exc}")
            continue

        if meta.severity < min_severity:
            continue
        for hit in hits:
            source = sources.get(hit.resource_id) or {}
            result.findings.append(
                Finding(
                    check_id=meta.id,
                    title=meta.title,
                    severity=meta.severity,
                    provider=meta.provider,
                    service=meta.service,
                    resource_id=hit.resource_id,
                    resource_name=hit.resource_name,
                    message=hit.message,
                    cis=meta.cis,
                    mitre=meta.mitre,
                    remediation=meta.remediation,
                    file=source.get("file"),
                    line=source.get("line"),
                )
            )

    result.findings.sort(key=lambda f: (-int(f.severity), f.check_id, f.resource_name))
    return result
