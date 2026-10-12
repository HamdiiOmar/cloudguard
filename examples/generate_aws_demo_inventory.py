"""Build examples/sample_inventory_aws.json without an AWS account.

moto simulates the AWS API locally, so this runs CloudGuard's real boto3 collector against
a fake account that contains a few deliberate misconfigurations.

    pip install -e ".[dev]"
    python examples/generate_aws_demo_inventory.py
    cloudguard scan --inventory examples/sample_inventory_aws.json
"""

from __future__ import annotations

import os
from pathlib import Path

OUTPUT = Path(__file__).resolve().parent / "sample_inventory_aws.json"
REGION = "eu-west-1"


def main() -> None:
    # Fake credentials so nothing can ever reach a real account from this script.
    os.environ.update(
        AWS_ACCESS_KEY_ID="testing",
        AWS_SECRET_ACCESS_KEY="testing",
        AWS_SESSION_TOKEN="testing",
        AWS_DEFAULT_REGION=REGION,
        AWS_EC2_METADATA_DISABLED="true",
    )

    import boto3
    from moto import mock_aws

    from cloudguard.providers.aws.collector import collect

    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        ec2 = boto3.client("ec2", region_name=REGION)
        location = {"LocationConstraint": REGION}

        # Public bucket: no Block Public Access, public-read ACL, no versioning.
        s3.create_bucket(Bucket="acme-marketing-assets", CreateBucketConfiguration=location)
        s3.put_bucket_acl(Bucket="acme-marketing-assets", ACL="public-read")

        # Hardened bucket.
        s3.create_bucket(Bucket="acme-customer-data", CreateBucketConfiguration=location)
        s3.put_public_access_block(
            Bucket="acme-customer-data",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        s3.put_bucket_versioning(
            Bucket="acme-customer-data", VersioningConfiguration={"Status": "Enabled"}
        )

        # Bastion-style group with SSH and RDP open to the Internet.
        bastion = ec2.create_security_group(GroupName="bastion", Description="bastion")["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=bastion,
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

        # Everything open: the worst case.
        ec2.authorize_security_group_ingress(
            GroupId=ec2.create_security_group(GroupName="temp-debug", Description="debug")[
                "GroupId"
            ],
            IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        )

        # Reasonable web tier.
        web = ec2.create_security_group(GroupName="web-tier", Description="web")["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=web,
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
                    "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
                },
            ],
        )

        inventory = collect(regions=[REGION])

    inventory.save(OUTPUT)
    print(f"Wrote {OUTPUT} ({len(inventory.get('s3_buckets'))} buckets, "
          f"{len(inventory.get('security_groups'))} security groups)")


if __name__ == "__main__":
    main()
