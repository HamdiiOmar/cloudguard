"""Human-readable report for the terminal."""

from __future__ import annotations

from cloudguard.engine import ScanResult


def render_console(result: ScanResult) -> str:
    lines: list[str] = []
    lines.append(f"CloudGuard scan: {result.provider} / {result.scope or 'n/a'}")
    lines.append(f"Checks run: {result.checks_run}   Findings: {len(result.findings)}")
    lines.append("")

    if not result.findings:
        lines.append("No findings.")
    for finding in result.findings:
        refs = []
        if finding.cis:
            refs.append("CIS " + ", ".join(finding.cis))
        if finding.mitre:
            refs.append("ATT&CK " + ", ".join(finding.mitre))
        lines.append(f"[{str(finding.severity).upper():8}] {finding.check_id}  {finding.title}")
        lines.append(f"           {finding.message}")
        if finding.file:
            lines.append(f"           at {finding.file}:{finding.line or 1}")
        if refs:
            lines.append(f"           {' | '.join(refs)}")
        if finding.remediation:
            lines.append(f"           Fix: {finding.remediation}")
        lines.append("")

    counts = result.count_by_severity()
    summary = "  ".join(f"{sev.name.lower()}={n}" for sev, n in counts.items())
    lines.append(f"Summary: {summary}")

    if result.warnings:
        lines.append("")
        lines.append("Collection warnings (these settings could not be read and were skipped):")
        lines.extend(f"  - {warning}" for warning in result.warnings)

    if result.errors:
        lines.append("")
        lines.append("Check errors (these checks did not complete):")
        lines.extend(f"  - {err}" for err in result.errors)

    return "\n".join(lines) + "\n"
