"""S3 bucket checks.

Bucket dicts are produced by ``cloudguard.providers.aws.collector``. A key that is absent
means the setting could not be collected (for example AccessDenied); checks skip those
buckets instead of guessing. ``public_access_block: None`` means "collected, and no
configuration exists".

Known limitation: only bucket-level Block Public Access is evaluated. An account-level
Block Public Access setting also protects buckets and is not modelled yet.
CIS references are to the CIS AWS Foundations Benchmark v3.0.0.
"""

from __future__ import annotations

from collections.abc import Iterator

from cloudguard.models import Hit, Inventory, Severity
from cloudguard.registry import check

PROVIDER = "aws"
SERVICE = "s3"

_PUBLIC_GROUPS = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "everyone",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "any AWS account",
}
_BPA_SETTINGS = (
    "block_public_acls",
    "ignore_public_acls",
    "block_public_policy",
    "restrict_public_buckets",
)


def _ident(bucket: dict) -> tuple[str, str]:
    name = bucket.get("name") or "<unnamed>"
    return bucket.get("id") or name, name


@check(
    id="CG-AWS-S3-001",
    title="S3 bucket does not enable all Block Public Access settings",
    description="Without all four Block Public Access settings, ACLs or policies can expose data.",
    severity=Severity.HIGH,
    provider=PROVIDER,
    service=SERVICE,
    cis=("2.1.4",),
    mitre=("T1530",),
    remediation="Enable all four Block Public Access settings on the bucket (and the account).",
)
def block_public_access(inventory: Inventory) -> Iterator[Hit]:
    for bucket in inventory.get("s3_buckets"):
        if "public_access_block" not in bucket:
            continue
        rid, name = _ident(bucket)
        config = bucket["public_access_block"]
        if not config:
            yield Hit(rid, name, f"Bucket '{name}' has no Block Public Access configuration.")
            continue
        missing = [key for key in _BPA_SETTINGS if not config.get(key)]
        if missing:
            yield Hit(
                rid,
                name,
                f"Bucket '{name}' does not enable: {', '.join(missing)}.",
            )


@check(
    id="CG-AWS-S3-002",
    title="S3 bucket ACL grants access to everyone",
    description="The bucket ACL grants permissions to AllUsers or AuthenticatedUsers.",
    severity=Severity.HIGH,
    provider=PROVIDER,
    service=SERVICE,
    mitre=("T1530",),
    remediation="Remove public grants from the bucket ACL and disable ACLs (Object Ownership).",
)
def public_acl(inventory: Inventory) -> Iterator[Hit]:
    for bucket in inventory.get("s3_buckets"):
        all_grants = bucket.get("acl_grants") or []
        grants = [g for g in all_grants if g.get("grantee_uri") in _PUBLIC_GROUPS]
        if grants:
            rid, name = _ident(bucket)
            who = sorted({_PUBLIC_GROUPS[g["grantee_uri"]] for g in grants})
            perms = sorted({str(g.get("permission")) for g in grants})
            yield Hit(
                rid,
                name,
                f"Bucket '{name}' ACL grants {'/'.join(perms)} to {' and '.join(who)}.",
            )


@check(
    id="CG-AWS-S3-003",
    title="S3 bucket versioning is not enabled",
    description="Without versioning, overwritten or deleted objects cannot be recovered.",
    severity=Severity.LOW,
    provider=PROVIDER,
    service=SERVICE,
    mitre=("T1485",),
    remediation="Enable versioning on the bucket and add a lifecycle rule for old versions.",
)
def versioning_enabled(inventory: Inventory) -> Iterator[Hit]:
    for bucket in inventory.get("s3_buckets"):
        status = bucket.get("versioning")
        if status in ("Disabled", "Suspended"):
            rid, name = _ident(bucket)
            yield Hit(rid, name, f"Bucket '{name}' versioning is {status.lower()}.")
