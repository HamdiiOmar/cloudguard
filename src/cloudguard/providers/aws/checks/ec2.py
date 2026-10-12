"""EC2 security group checks.

Security group dicts are produced by ``cloudguard.providers.aws.collector``; ``ingress``
holds one entry per IP permission with ``protocol``, ``from_port``, ``to_port``,
``ipv4_ranges`` and ``ipv6_ranges``.

SSH/RDP checks look at TCP rules whose port range includes the port. A rule using protocol
``-1`` (all traffic) is reported once by CG-AWS-EC2-003 instead of also triggering the
port-specific checks. Security group references and prefix lists are not treated as the
Internet. CIS references are to the CIS AWS Foundations Benchmark v3.0.0.
"""

from __future__ import annotations

from collections.abc import Iterator

from cloudguard.models import Hit, Inventory, Severity
from cloudguard.registry import check

PROVIDER = "aws"
SERVICE = "ec2"

_INTERNET_V4 = "0.0.0.0/0"
_INTERNET_V6 = "::/0"


def _internet_sources(rule: dict) -> list[str]:
    sources = []
    if _INTERNET_V4 in (rule.get("ipv4_ranges") or []):
        sources.append(_INTERNET_V4)
    if _INTERNET_V6 in (rule.get("ipv6_ranges") or []):
        sources.append(_INTERNET_V6)
    return sources


def _tcp_covers(rule: dict, port: int) -> bool:
    if (rule.get("protocol") or "").lower() != "tcp":
        return False
    low, high = rule.get("from_port"), rule.get("to_port")
    if low is None or high is None:
        return False
    return low <= port <= high


def _ident(group: dict) -> tuple[str, str]:
    name = group.get("name") or group.get("group_id") or "<unnamed>"
    return group.get("id") or name, name


def _exposed_port_hits(inventory: Inventory, port: int, label: str) -> Iterator[Hit]:
    for group in inventory.get("security_groups"):
        sources: set[str] = set()
        for rule in group.get("ingress") or []:
            if _tcp_covers(rule, port):
                sources.update(_internet_sources(rule))
        if sources:
            rid, name = _ident(group)
            yield Hit(
                rid,
                name,
                f"Security group '{name}' allows {label} (TCP {port}) from "
                f"{', '.join(sorted(sources))}.",
            )


@check(
    id="CG-AWS-EC2-001",
    title="Security group allows SSH (22) from the Internet",
    description="An ingress rule exposes SSH to 0.0.0.0/0 or ::/0.",
    severity=Severity.HIGH,
    provider=PROVIDER,
    service=SERVICE,
    cis=("5.2", "5.3"),
    mitre=("T1021.004", "T1133"),
    remediation="Restrict the source to trusted CIDR ranges or use SSM Session Manager.",
)
def ssh_open_to_internet(inventory: Inventory) -> Iterator[Hit]:
    yield from _exposed_port_hits(inventory, 22, "SSH")


@check(
    id="CG-AWS-EC2-002",
    title="Security group allows RDP (3389) from the Internet",
    description="An ingress rule exposes Remote Desktop to 0.0.0.0/0 or ::/0.",
    severity=Severity.HIGH,
    provider=PROVIDER,
    service=SERVICE,
    cis=("5.2", "5.3"),
    mitre=("T1021.001", "T1133"),
    remediation="Restrict the source to trusted CIDR ranges or use SSM Session Manager.",
)
def rdp_open_to_internet(inventory: Inventory) -> Iterator[Hit]:
    yield from _exposed_port_hits(inventory, 3389, "RDP")


@check(
    id="CG-AWS-EC2-003",
    title="Security group allows all traffic from the Internet",
    description="An ingress rule for all protocols and ports is open to 0.0.0.0/0 or ::/0.",
    severity=Severity.CRITICAL,
    provider=PROVIDER,
    service=SERVICE,
    cis=("5.2", "5.3"),
    mitre=("T1190", "T1133"),
    remediation="Replace the rule with specific ports and trusted source ranges.",
)
def all_traffic_open_to_internet(inventory: Inventory) -> Iterator[Hit]:
    for group in inventory.get("security_groups"):
        sources: set[str] = set()
        for rule in group.get("ingress") or []:
            if str(rule.get("protocol")) == "-1":
                sources.update(_internet_sources(rule))
        if sources:
            rid, name = _ident(group)
            yield Hit(
                rid,
                name,
                f"Security group '{name}' allows all traffic from {', '.join(sorted(sources))}.",
            )
