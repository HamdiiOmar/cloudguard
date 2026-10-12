"""Storage account checks.

Resource dicts follow the shape of ``StorageAccount.as_dict()`` from azure-mgmt-storage.
CIS references are to the CIS Microsoft Azure Foundations Benchmark v2.0.0.
"""

from __future__ import annotations

from collections.abc import Iterator

from cloudguard.models import Hit, Inventory, Severity
from cloudguard.registry import check

PROVIDER = "azure"
SERVICE = "storage"
_INSECURE_TLS = {"TLS1_0", "TLS1_1"}


def _ident(account: dict) -> tuple[str, str]:
    name = account.get("name") or "<unnamed>"
    return account.get("id") or name, name


@check(
    id="CG-AZ-STG-001",
    title="Storage account allows public blob access",
    description="Containers in this account can be configured for anonymous read access.",
    severity=Severity.HIGH,
    provider=PROVIDER,
    service=SERVICE,
    cis=("3.7",),
    mitre=("T1530",),
    remediation="Set 'Allow Blob anonymous access' to Disabled on the storage account.",
)
def public_blob_access(inventory: Inventory) -> Iterator[Hit]:
    for account in inventory.get("storage_accounts"):
        if account.get("allow_blob_public_access") is True:
            rid, name = _ident(account)
            yield Hit(rid, name, f"Storage account '{name}' allows anonymous blob access.")


@check(
    id="CG-AZ-STG-002",
    title="Storage account does not require secure transfer",
    description="Requests over plain HTTP are accepted, exposing data and keys in transit.",
    severity=Severity.MEDIUM,
    provider=PROVIDER,
    service=SERVICE,
    cis=("3.1",),
    mitre=("T1557",),
    remediation="Enable 'Secure transfer required' on the storage account.",
)
def secure_transfer_required(inventory: Inventory) -> Iterator[Hit]:
    for account in inventory.get("storage_accounts"):
        if account.get("enable_https_traffic_only") is False:
            rid, name = _ident(account)
            yield Hit(rid, name, f"Storage account '{name}' accepts unencrypted HTTP requests.")


@check(
    id="CG-AZ-STG-003",
    title="Storage account allows TLS older than 1.2",
    description="The minimum accepted TLS version is below 1.2.",
    severity=Severity.MEDIUM,
    provider=PROVIDER,
    service=SERVICE,
    cis=("3.15",),
    mitre=("T1557",),
    remediation="Set the minimum TLS version of the storage account to 1.2.",
)
def minimum_tls_version(inventory: Inventory) -> Iterator[Hit]:
    for account in inventory.get("storage_accounts"):
        version = account.get("minimum_tls_version")
        if version in _INSECURE_TLS:
            rid, name = _ident(account)
            yield Hit(rid, name, f"Storage account '{name}' minimum TLS version is {version}.")


@check(
    id="CG-AZ-STG-004",
    title="Storage account firewall default action is Allow",
    description="Without a restrictive default rule, the account is reachable from any network.",
    severity=Severity.HIGH,
    provider=PROVIDER,
    service=SERVICE,
    cis=("3.8",),
    mitre=("T1530",),
    remediation="Set the default network access rule to Deny and allow only required networks.",
)
def default_network_action_deny(inventory: Inventory) -> Iterator[Hit]:
    for account in inventory.get("storage_accounts"):
        rules = account.get("network_rule_set") or {}
        if (rules.get("default_action") or "").lower() == "allow":
            rid, name = _ident(account)
            yield Hit(rid, name, f"Storage account '{name}' firewall default action is Allow.")
