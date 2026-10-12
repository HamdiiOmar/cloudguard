"""Collect an AWS inventory with boto3.

Requires the ``aws`` extra: ``pip install "cloudguard-cspm[aws]"``.
Credentials come from the normal boto3 chain (environment, ``~/.aws``, SSO, instance role).
Only read-only API calls are made (``s3:ListAllMyBuckets``, ``s3:GetBucket*``,
``ec2:DescribeSecurityGroups``, ``iam:GetAccountSummary``, ``iam:List*``, ``iam:GetLoginProfile``,
``iam:GetPolicyVersion``, ``sts:GetCallerIdentity``). The ``SecurityAudit`` managed policy
covers all of them.

boto3 responses are normalised to snake_case dicts so that checks never depend on boto3's
response shapes. A call that fails (for example AccessDenied) adds a warning and leaves
the field out, so a check skips that resource instead of reporting a false finding.
"""

from __future__ import annotations

from typing import Any

from cloudguard.models import Inventory

try:  # optional dependency; collect() reports a clear error when it is missing
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:  # pragma: no cover
    BotoCoreError = ClientError = Exception  # type: ignore[assignment,misc]

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

    iam = session.client("iam")
    return Inventory(
        provider="aws",
        scope=account,
        resources={
            "s3_buckets": buckets,
            "security_groups": groups,
            "iam_account": _collect_iam_account(iam, account, call),
            "iam_users": _collect_iam_users(iam, call, warnings),
            "iam_policies": _collect_iam_policies(iam, call, warnings),
        },
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


# ----------------------------------------------------------------------------- IAM


def _collect_iam_account(iam: Any, account: str, call: Any) -> list[dict[str, Any]]:
    item: dict[str, Any] = {"id": f"arn:aws:iam::{account}:root", "name": "root account"}
    resp = call("iam:GetAccountSummary", iam.get_account_summary)
    if resp is not _UNKNOWN and resp is not None:
        summary = resp.get("SummaryMap", {})
        if "AccountAccessKeysPresent" in summary:
            item["root_access_keys_present"] = int(summary["AccountAccessKeysPresent"])
    return [item]


def _collect_iam_users(iam: Any, call: Any, warnings: list[str]) -> list[dict[str, Any]]:
    users: list[dict[str, Any]] = []
    try:
        raw_users = [
            u for page in iam.get_paginator("list_users").paginate() for u in page["Users"]
        ]
    except (BotoCoreError, ClientError) as exc:
        warnings.append(f"iam:ListUsers: {exc}")
        return users

    for raw in raw_users:
        name = raw["UserName"]
        user: dict[str, Any] = {"id": raw["Arn"], "name": name}

        resp = call(
            f"iam:GetLoginProfile {name}",
            iam.get_login_profile,
            missing_code="NoSuchEntity",
            UserName=name,
        )
        if resp is None:
            user["console_access"] = False
        elif resp is not _UNKNOWN:
            user["console_access"] = True

        resp = call(f"iam:ListMFADevices {name}", iam.list_mfa_devices, UserName=name)
        if resp is not _UNKNOWN and resp is not None:
            user["mfa_enabled"] = bool(resp.get("MFADevices"))

        resp = call(f"iam:ListAccessKeys {name}", iam.list_access_keys, UserName=name)
        if resp is not _UNKNOWN and resp is not None:
            user["access_keys"] = [
                {
                    "id": k["AccessKeyId"],
                    "status": k["Status"],
                    "created": k["CreateDate"].isoformat(),
                }
                for k in resp.get("AccessKeyMetadata", [])
            ]
        users.append(user)
    return users


def _collect_iam_policies(iam: Any, call: Any, warnings: list[str]) -> list[dict[str, Any]]:
    """Customer-managed policies (Scope=Local). Inline policies are not collected yet."""
    policies: list[dict[str, Any]] = []
    try:
        raw = [
            p
            for page in iam.get_paginator("list_policies").paginate(Scope="Local")
            for p in page["Policies"]
        ]
    except (BotoCoreError, ClientError) as exc:
        warnings.append(f"iam:ListPolicies: {exc}")
        return policies

    for entry in raw:
        resp = call(
            f"iam:GetPolicyVersion {entry['PolicyName']}",
            iam.get_policy_version,
            PolicyArn=entry["Arn"],
            VersionId=entry["DefaultVersionId"],
        )
        if resp is _UNKNOWN or resp is None:
            continue
        policies.append(
            {
                "id": entry["Arn"],
                "name": entry["PolicyName"],
                "document": resp["PolicyVersion"]["Document"],
            }
        )
    return policies
