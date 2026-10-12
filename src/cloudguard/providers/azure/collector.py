"""Collect an Azure inventory with the Azure SDK.

Requires the ``azure`` extra: ``pip install "cloudguard-cspm[azure]"``.
Authentication uses DefaultAzureCredential, so ``az login``, environment variables
or a managed identity all work. Only read operations are performed.
"""

from __future__ import annotations

from cloudguard.models import Inventory


def collect(subscription_id: str) -> Inventory:
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient
        from azure.mgmt.storage import StorageManagementClient
    except ImportError as exc:
        raise RuntimeError(
            'Azure SDK not installed. Run: pip install "cloudguard-cspm[azure]"'
        ) from exc

    credential = DefaultAzureCredential()
    storage = StorageManagementClient(credential, subscription_id)
    network = NetworkManagementClient(credential, subscription_id)

    return Inventory(
        provider="azure",
        scope=subscription_id,
        resources={
            "storage_accounts": [a.as_dict() for a in storage.storage_accounts.list()],
            "network_security_groups": [
                n.as_dict() for n in network.network_security_groups.list_all()
            ],
        },
    )
