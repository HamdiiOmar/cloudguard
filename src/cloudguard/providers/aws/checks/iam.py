"""IAM checks.

Inventory resources (produced by the AWS collector, or by the Terraform reader for policies):

* ``iam_account``  - one entry with ``root_access_keys_present`` (int). Live accounts only.
* ``iam_users``    - ``console_access``, ``mfa_enabled`` and ``access_keys`` (each with
  ``status`` and an ISO ``created`` timestamp). Live accounts only: Terraform cannot show
  whether a person enrolled an MFA device.
* ``iam_policies`` - ``document``: the parsed policy JSON.

A key that is absent means the setting could not be read, so the check skips it rather than
guess. Not modelled yet: inline policies on live users/roles, permission boundaries, SCPs,
and policies that are admin through ``NotAction``. CIS references are to the CIS AWS
Foundations Benchmark v3.0.0 and should be verified.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone

from cloudguard.models import Hit, Inventory, Severity
from cloudguard.registry import check

PROVIDER = "aws"
SERVICE = "iam"
MAX_KEY_AGE_DAYS = 90


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


@check(
    id="CG-AWS-IAM-001",
    title="Root account has active access keys",
    description="Access keys on the root user bypass IAM policies and are rarely rotated.",
    severity=Severity.CRITICAL,
    provider=PROVIDER,
    service=SERVICE,
    cis=("1.4",),
    mitre=("T1078.004",),
    remediation="Delete the root access keys and use IAM roles or Identity Center instead.",
)
def root_access_keys(inventory: Inventory) -> Iterator[Hit]:
    for account in inventory.get("iam_account"):
        count = account.get("root_access_keys_present")
        if count:
            yield Hit(
                account.get("id", "root"),
                account.get("name", "root account"),
                f"The root account has {count} access key(s).",
            )


@check(
    id="CG-AWS-IAM-002",
    title="IAM user with console access has no MFA",
    description="A password alone protects the console login of this user.",
    severity=Severity.HIGH,
    provider=PROVIDER,
    service=SERVICE,
    cis=("1.10",),
    mitre=("T1078.004",),
    remediation="Enroll an MFA device for the user, or remove console access.",
)
def console_user_without_mfa(inventory: Inventory) -> Iterator[Hit]:
    for user in inventory.get("iam_users"):
        if user.get("console_access") is True and user.get("mfa_enabled") is False:
            name = user.get("name", "<unnamed>")
            yield Hit(
                user.get("id", name), name, f"User '{name}' can sign in to the console without MFA."
            )


@check(
    id="CG-AWS-IAM-003",
    title="IAM policy grants full administrative privileges",
    description="An Allow statement with Action '*' on Resource '*' grants unrestricted access.",
    severity=Severity.HIGH,
    provider=PROVIDER,
    service=SERVICE,
    cis=("1.16",),
    mitre=("T1078.004",),
    remediation="Replace the wildcard with the specific actions and resources that are needed.",
)
def wildcard_admin_policy(inventory: Inventory) -> Iterator[Hit]:
    for policy in inventory.get("iam_policies"):
        document = policy.get("document")
        if not isinstance(document, dict):
            continue
        for statement in _as_list(document.get("Statement")):
            if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
                continue
            if "*" in _as_list(statement.get("Action")) and "*" in _as_list(
                statement.get("Resource")
            ):
                name = policy.get("name", "<unnamed>")
                yield Hit(
                    policy.get("id", name),
                    name,
                    f"Policy '{name}' allows Action '*' on Resource '*'.",
                )
                break  # one finding per policy


def _age_days(created: str, now: datetime) -> int | None:
    try:
        when = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (now - when).days


@check(
    id="CG-AWS-IAM-004",
    title="IAM access key has not been rotated in 90 days",
    description="Long-lived access keys increase the window in which a leaked key is usable.",
    severity=Severity.MEDIUM,
    provider=PROVIDER,
    service=SERVICE,
    cis=("1.14",),
    mitre=("T1078.004",),
    remediation="Rotate the key, then deactivate and delete the old one.",
)
def stale_access_keys(inventory: Inventory) -> Iterator[Hit]:
    now = datetime.now(timezone.utc)
    for user in inventory.get("iam_users"):
        for key in user.get("access_keys") or []:
            if key.get("status") != "Active":
                continue
            age = _age_days(key.get("created", ""), now)
            if age is not None and age > MAX_KEY_AGE_DAYS:
                name = user.get("name", "<unnamed>")
                yield Hit(
                    user.get("id", name),
                    name,
                    f"User '{name}' has an active access key {key.get('id', '')} "
                    f"that is {age} days old.",
                )
