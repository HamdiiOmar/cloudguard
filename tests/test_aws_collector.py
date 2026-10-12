"""End-to-end tests: real boto3 calls against moto's simulated AWS, no account needed."""

import pytest

pytest.importorskip("boto3")
pytest.importorskip("moto")

import boto3  # noqa: E402
from moto import mock_aws  # noqa: E402

from cloudguard.engine import run_scan  # noqa: E402
from cloudguard.providers.aws.collector import collect  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_env(monkeypatch):
    for key, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": REGION,
        "AWS_EC2_METADATA_DISABLED": "true",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@pytest.fixture
def aws():
    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        ec2 = boto3.client("ec2", region_name=REGION)

        s3.create_bucket(Bucket="cg-public-bad")
        s3.put_bucket_acl(Bucket="cg-public-bad", ACL="public-read")

        s3.create_bucket(Bucket="cg-private-good")
        s3.put_public_access_block(
            Bucket="cg-private-good",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        s3.put_bucket_versioning(
            Bucket="cg-private-good", VersioningConfiguration={"Status": "Enabled"}
        )

        web = ec2.create_security_group(GroupName="web", Description="web")["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=web,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                },
            ],
        )

        wide = ec2.create_security_group(GroupName="wide-open", Description="all")["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=wide,
            IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        )

        safe = ec2.create_security_group(GroupName="safe", Description="safe")["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=safe,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                },
            ],
        )
        yield


def test_collect_shape(aws):
    inventory = collect(regions=[REGION])

    assert inventory.provider == "aws"
    assert inventory.scope == "123456789012"  # moto's fake account
    assert inventory.warnings == []

    buckets = {b["name"]: b for b in inventory.get("s3_buckets")}
    assert buckets["cg-public-bad"]["public_access_block"] is None
    assert buckets["cg-public-bad"]["versioning"] == "Disabled"
    public_grants = buckets["cg-public-bad"]["acl_grants"]
    assert any(g["grantee_uri"].endswith("/AllUsers") for g in public_grants)
    assert all(buckets["cg-private-good"]["public_access_block"].values())
    assert buckets["cg-private-good"]["versioning"] == "Enabled"
    assert buckets["cg-private-good"]["id"] == "arn:aws:s3:::cg-private-good"

    groups = {g["name"].split(" ")[0]: g for g in inventory.get("security_groups")}
    assert {"web", "wide-open", "safe"} <= set(groups)
    assert groups["web"]["region"] == REGION
    assert groups["web"]["id"].startswith(f"arn:aws:ec2:{REGION}:123456789012:security-group/sg-")
    ssh = next(r for r in groups["web"]["ingress"] if r["from_port"] == 22)
    assert ssh["ipv4_ranges"] == ["0.0.0.0/0"]


def test_full_scan_finds_the_planted_misconfigurations(aws):
    result = run_scan(collect(regions=[REGION]))
    assert result.errors == []

    flagged: dict[str, set[str]] = {}
    for finding in result.findings:
        flagged.setdefault(finding.check_id, set()).add(finding.resource_name.split(" ")[0])

    assert flagged["CG-AWS-S3-001"] == {"cg-public-bad"}
    assert flagged["CG-AWS-S3-002"] == {"cg-public-bad"}
    assert flagged["CG-AWS-S3-003"] == {"cg-public-bad"}
    assert flagged["CG-AWS-EC2-001"] == {"web"}
    assert flagged["CG-AWS-EC2-002"] == {"web"}
    assert flagged["CG-AWS-EC2-003"] == {"wide-open"}


def test_clean_resources_produce_no_findings(aws):
    result = run_scan(collect(regions=[REGION]))
    names = {f.resource_name.split(" ")[0] for f in result.findings}
    assert "cg-private-good" not in names
    assert "safe" not in names


def test_default_region_comes_from_environment(aws):
    assert collect().get("security_groups")


def test_unreadable_setting_becomes_warning_not_false_finding(aws, monkeypatch):
    from botocore.exceptions import ClientError

    real_client = boto3.Session.client

    def client_with_denied_acl(self, service_name, *args, **kwargs):
        client = real_client(self, service_name, *args, **kwargs)
        if service_name == "s3":

            def denied(**_kwargs):
                raise ClientError({"Error": {"Code": "AccessDenied"}}, "GetBucketAcl")

            client.get_bucket_acl = denied
        return client

    monkeypatch.setattr(boto3.Session, "client", client_with_denied_acl)

    inventory = collect(regions=[REGION])
    assert any("GetBucketAcl cg-public-bad: AccessDenied" in w for w in inventory.warnings)
    assert all("acl_grants" not in b for b in inventory.get("s3_buckets"))

    result = run_scan(inventory)
    assert "CG-AWS-S3-002" not in {f.check_id for f in result.findings}
    assert result.warnings == inventory.warnings
