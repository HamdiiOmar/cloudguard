"""Network security group checks.

Resource dicts follow the shape of ``NetworkSecurityGroup.as_dict()`` from azure-mgmt-network.
Only custom rules (``security_rules``) are evaluated; Azure's default inbound rules do not
allow Internet traffic.

Known limitation: rule evaluation is a simplification. It honours rule priority and a
lower-numbered Deny, but does not model service tags other than Internet/Any, application
security groups, or subnet-vs-NIC NSG layering.
"""

from __future__ import annotations

from collections.abc import Iterator

from cloudguard.models import Hit, Inventory, Severity
from cloudguard.registry import check

PROVIDER = "azure"
SERVICE = "network"

_INTERNET_SOURCES = {"*", "0.0.0.0/0", "::/0", "internet", "any"}
_DEFAULT_PRIORITY = 65000


def _port_matches(spec: str, port: int) -> bool:
    spec = spec.strip()
    if spec == "*":
        return True
    try:
        if "-" in spec:
            low, high = spec.split("-", 1)
            return int(low) <= port <= int(high)
        return int(spec) == port
    except ValueError:
        return False


def _collect(rule: dict, singular: str, plural: str) -> list[str]:
    values: list[str] = []
    if rule.get(singular):
        values.append(str(rule[singular]))
    values.extend(str(v) for v in rule.get(plural) or [])
    return values


def _matches_internet_tcp_port(rule: dict, port: int) -> bool:
    sources = _collect(rule, "source_address_prefix", "source_address_prefixes")
    if not any(s.lower() in _INTERNET_SOURCES for s in sources):
        return False
    if (rule.get("protocol") or "").lower() not in {"tcp", "*"}:
        return False
    ports = _collect(rule, "destination_port_range", "destination_port_ranges")
    return any(_port_matches(p, port) for p in ports)


def internet_allow_rules(nsg: dict, port: int) -> list[dict]:
    """Return inbound Allow rules that expose ``port`` to the Internet.

    Rules are evaluated in priority order (lowest number first). A matching Deny stops
    evaluation, so Allow rules with a higher priority number are shadowed by it.
    """
    rules = nsg.get("security_rules") or []
    inbound = [r for r in rules if (r.get("direction") or "").lower() == "inbound"]
    inbound.sort(key=lambda r: r.get("priority", _DEFAULT_PRIORITY))

    exposing: list[dict] = []
    for rule in inbound:
        if not _matches_internet_tcp_port(rule, port):
            continue
        if (rule.get("access") or "").lower() == "deny":
            break
        exposing.append(rule)
    return exposing


def _exposed_port_hits(inventory: Inventory, port: int, label: str) -> Iterator[Hit]:
    for nsg in inventory.get("network_security_groups"):
        name = nsg.get("name") or "<unnamed>"
        rid = nsg.get("id") or name
        for rule in internet_allow_rules(nsg, port):
            yield Hit(
                rid,
                name,
                f"NSG '{name}' rule '{rule.get('name', '?')}' allows {label} (TCP {port}) "
                "from the Internet.",
            )


@check(
    id="CG-AZ-NET-001",
    title="NSG allows RDP (3389) from the Internet",
    description="An inbound Allow rule exposes Remote Desktop to any source address.",
    severity=Severity.HIGH,
    provider=PROVIDER,
    service=SERVICE,
    cis=("6.1",),
    mitre=("T1021.001", "T1133"),
    remediation="Restrict the source to trusted IP ranges or use Azure Bastion / JIT access.",
)
def rdp_open_to_internet(inventory: Inventory) -> Iterator[Hit]:
    yield from _exposed_port_hits(inventory, 3389, "RDP")


@check(
    id="CG-AZ-NET-002",
    title="NSG allows SSH (22) from the Internet",
    description="An inbound Allow rule exposes SSH to any source address.",
    severity=Severity.HIGH,
    provider=PROVIDER,
    service=SERVICE,
    cis=("6.2",),
    mitre=("T1021.004", "T1133"),
    remediation="Restrict the source to trusted IP ranges or use Azure Bastion / JIT access.",
)
def ssh_open_to_internet(inventory: Inventory) -> Iterator[Hit]:
    yield from _exposed_port_hits(inventory, 22, "SSH")
