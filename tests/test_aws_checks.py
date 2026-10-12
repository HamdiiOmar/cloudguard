from cloudguard.engine import run_scan
from cloudguard.models import Inventory

BPA_ALL = {
    "block_public_acls": True,
    "ignore_public_acls": True,
    "block_public_policy": True,
    "restrict_public_buckets": True,
}
ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


def _inv(**resources) -> Inventory:
    return Inventory(provider="aws", scope="123456789012", resources=resources)


def _ids(**resources) -> set[str]:
    return {f.check_id for f in run_scan(_inv(**resources)).findings}


def _sg(*rules, name="sg"):
    return {"name": name, "ingress": list(rules)}


def _tcp(port, *, v4=("0.0.0.0/0",), v6=(), to_port=None):
    return {
        "protocol": "tcp",
        "from_port": port,
        "to_port": to_port if to_port is not None else port,
        "ipv4_ranges": list(v4),
        "ipv6_ranges": list(v6),
    }


# ---- S3 ----


def test_bucket_without_public_access_block_flagged():
    assert "CG-AWS-S3-001" in _ids(s3_buckets=[{"name": "b", "public_access_block": None}])


def test_bucket_with_partial_public_access_block_flagged():
    partial = {**BPA_ALL, "block_public_policy": False}
    result = run_scan(_inv(s3_buckets=[{"name": "b", "public_access_block": partial}]))
    assert [f.check_id for f in result.findings] == ["CG-AWS-S3-001"]
    assert "block_public_policy" in result.findings[0].message


def test_bucket_with_full_public_access_block_not_flagged():
    assert "CG-AWS-S3-001" not in _ids(s3_buckets=[{"name": "b", "public_access_block": BPA_ALL}])


def test_uncollected_public_access_block_is_skipped_not_flagged():
    assert "CG-AWS-S3-001" not in _ids(s3_buckets=[{"name": "b"}])


def test_public_acl_flagged_for_both_public_groups():
    for uri in (ALL_USERS, AUTH_USERS):
        grants = [{"grantee_uri": uri, "permission": "READ"}]
        assert "CG-AWS-S3-002" in _ids(s3_buckets=[{"name": "b", "acl_grants": grants}])


def test_private_acl_not_flagged():
    log_group = "http://acs.amazonaws.com/groups/s3/LogDelivery"
    grants = [{"grantee_uri": log_group, "permission": "WRITE"}]
    assert "CG-AWS-S3-002" not in _ids(s3_buckets=[{"name": "b", "acl_grants": grants}])


def test_versioning_disabled_or_suspended_flagged():
    for status in ("Disabled", "Suspended"):
        assert "CG-AWS-S3-003" in _ids(s3_buckets=[{"name": "b", "versioning": status}])


def test_versioning_enabled_or_unknown_not_flagged():
    assert "CG-AWS-S3-003" not in _ids(s3_buckets=[{"name": "b", "versioning": "Enabled"}])
    assert "CG-AWS-S3-003" not in _ids(s3_buckets=[{"name": "b"}])


# ---- Security groups ----


def test_ssh_open_to_ipv4_internet_flagged():
    assert "CG-AWS-EC2-001" in _ids(security_groups=[_sg(_tcp(22))])


def test_rdp_open_to_ipv6_internet_flagged():
    ids = _ids(security_groups=[_sg(_tcp(3389, v4=(), v6=("::/0",)))])
    assert "CG-AWS-EC2-002" in ids
    assert "CG-AWS-EC2-001" not in ids


def test_port_range_including_ssh_flagged():
    assert "CG-AWS-EC2-001" in _ids(security_groups=[_sg(_tcp(0, to_port=65535))])


def test_restricted_source_not_flagged():
    assert _ids(security_groups=[_sg(_tcp(22, v4=("10.0.0.0/8",)))]) == set()


def test_other_port_open_to_internet_not_flagged():
    assert _ids(security_groups=[_sg(_tcp(443))]) == set()


def test_udp_not_flagged():
    rule = {**_tcp(22), "protocol": "udp"}
    assert _ids(security_groups=[_sg(rule)]) == set()


def test_all_traffic_flagged_once_as_critical():
    rule = {
        "protocol": "-1",
        "from_port": None,
        "to_port": None,
        "ipv4_ranges": ["0.0.0.0/0"],
        "ipv6_ranges": [],
    }
    result = run_scan(_inv(security_groups=[_sg(rule)]))
    assert [f.check_id for f in result.findings] == ["CG-AWS-EC2-003"]
    assert str(result.findings[0].severity) == "critical"


def test_one_finding_per_group_even_with_several_matching_rules():
    group = _sg(_tcp(22), _tcp(22, v4=(), v6=("::/0",)), _tcp(20, to_port=30))
    result = run_scan(_inv(security_groups=[group]))
    ssh = [f for f in result.findings if f.check_id == "CG-AWS-EC2-001"]
    assert len(ssh) == 1
    assert "0.0.0.0/0" in ssh[0].message and "::/0" in ssh[0].message


def test_group_without_rules_is_fine():
    result = run_scan(_inv(security_groups=[{"name": "empty"}]))
    assert result.findings == []
    assert result.errors == []
