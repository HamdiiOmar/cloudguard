"""Collect an AWS inventory with boto3.

Requires the ``aws`` extra: ``pip install "cloudguard-cspm[aws]"``.
Credentials come from the normal boto3 chain (environment, ``~/.aws``, SSO, instance role).
Only read-only API calls are made (``s3:ListAllMyBuckets``, ``s3:GetBucket*``,
``ec2:DescribeSecurityGroups``, ``sts:GetCallerIdentity``).

boto3 responses are normalised to snake_case dicts so that checks never depend on boto3's
response shapes. A call that fails (for example AccessDenied) adds a warning and leaves
the field out, so a check skips that resource instead of reporting a false finding.
"""

from __future__ import annotations

from typing import Any

from cloudguard.models import Inventory

_UNKNOWN = object()
_BPA_FIELDS = {
    "BlockPublicAcls": "block_public_acls",
    "IgnorePublicAcls": "ignore_public_acls",
    "BlockPublicPolicy": "block_public_policy",
    "RestrictPublicBuckets": "restrict_public_buckets",
}


def collect(
    regions: list[str] | None = None,
    profile: str | None = None,
    all_regions: bool = False,
) -> Inventory:
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError as exc:
        raise RuntimeError(
            'boto3 is not installed. Run: pip install "cloudguard-cspm[aws]"'
        ) from exc

    warnings: list[str] = []

    def call(label: str, fn: Any, *, missing_code: str | None = None, **kwargs: Any) -> Any:
        """Call an API. Returns the response, None for a 'not configured' error code,
        or _UNKNOWN (with a warning recorded) for any other failure."""
        try:
            return fn(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "") or type(exc).__name__
            if missing_code and code == missing_code:
                return None
            warnings.append(f"{label}: {code}")
            return _UNKNOWN

    try:
        session = boto3.Session(profile_name=profile)
        account = session.client("sts").get_caller_identity()["Account"]
        default_region = session.region_name or "us-east-1"
        if all_regions:
            ec2_default = session.client("ec2", region_name=default_region)
            regions = [r["RegionName"] for r in ec2_default.describe_regions()["Regions"]]
        elif not regions:
            regions = [default_region]
        s3 = session.client("s3")
        raw_buckets = s3.list_buckets().get("Buckets", [])
    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(f"AWS error: {exc}") from exc

    buckets = [_collect_bucket(s3, b["Name"], call) for b in raw_buckets]

    groups: list[dict[str, Any]] = []
    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            for page in ec2.get_paginator("describe_security_groups").paginate():
                groups.extend(_normalise_group(g, region, account) for g in page["SecurityGroups"])
        except (BotoCoreError, ClientError) as exc:
            warnings.append(f"ec2:DescribeSecurityGroups {region}: {exc}")

    return Inventory(
        provider="aws",
        scope=account,
        resources={"s3_buckets": buckets, "security_groups": groups},
        warnings=warnings,
    )


def _collect_bucket(s3: Any, name: str, call: Any) -> dict[str, Any]:
    bucket: dict[str, Any] = {"id": f"arn:aws:s3:::{name}", "name": name}

    resp = call(
        f"s3:GetPublicAccessBlock {name}",
        s3.get_public_access_block,
        missing_code="NoSuchPublicAccessBlockConfiguration",
        Bucket=name,
    )
    if resp is None:
        bucket["public_access_block"] = None
    elif resp is not _UNKNOWN:
        config = resp["PublicAccessBlockConfiguration"]
        bucket["public_access_block"] = {
            snake: bool(config.get(camel)) for camel, snake in _BPA_FIELDS.items()
        }

    resp = call(f"s3:GetBucketAcl {name}", s3.get_bucket_acl, Bucket=name)
    if resp is not _UNKNOWN and resp is not None:
        bucket["acl_grants"] = [
            {"grantee_uri": g["Grantee"]["URI"], "permission": g.get("Permission")}
            for g in resp.get("Grants", [])
            if g.get("Grantee", {}).get("URI")
        ]

    resp = call(f"s3:GetBucketVersioning {name}", s3.get_bucket_versioning, Bucket=name)
    if resp is not _UNKNOWN and resp is not None:
        bucket["versioning"] = resp.get("Status", "Disabled")

    return bucket


def _normalise_group(group: dict[str, Any], region: str, account: str) -> dict[str, Any]:
    group_id = group["GroupId"]
    ingress = [
        {
            "protocol": perm.get("IpProtocol"),
            "from_port": perm.get("FromPort"),
            "to_port": perm.get("ToPort"),
            "ipv4_ranges": [r["CidrIp"] for r in perm.get("IpRanges", []) if "CidrIp" in r],
            "ipv6_ranges": [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if "CidrIpv6" in r],
        }
        for perm in group.get("IpPermissions", [])
    ]
    return {
        "id": f"arn:aws:ec2:{region}:{account}:security-group/{group_id}",
        "group_id": group_id,
        "name": f"{group.get('GroupName', '')} ({group_id})",
        "region": region,
        "vpc_id": group.get("VpcId"),
        "ingress": ingress,
    }
