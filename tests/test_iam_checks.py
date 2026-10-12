from datetime import datetime, timedelta, timezone

from cloudguard.engine import run_scan
from cloudguard.models import Inventory


def inv(**resources) -> Inventory:
    return Inventory(provider="aws", scope="123456789012", resources=resources)


def flagged(inventory, check_id):
    result = run_scan(inventory, only=[check_id])
    assert result.errors == []
    return [f.resource_name for f in result.findings]


def days_ago(n: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=n)).isoformat()


# ------------------------------------------------------------------ IAM-001 root keys


def test_root_with_access_keys_is_flagged():
    account = {"id": "arn:aws:iam::1:root", "name": "root account", "root_access_keys_present": 1}
    assert flagged(inv(iam_account=[account]), "CG-AWS-IAM-001") == ["root account"]


def test_root_without_keys_or_unknown_is_not_flagged():
    clean = {"id": "r", "name": "root account", "root_access_keys_present": 0}
    unknown = {"id": "r", "name": "root account"}  # AccessDenied: key left out
    assert flagged(inv(iam_account=[clean]), "CG-AWS-IAM-001") == []
    assert flagged(inv(iam_account=[unknown]), "CG-AWS-IAM-001") == []


# ------------------------------------------------------------------- IAM-002 user MFA


def test_console_user_without_mfa_is_flagged():
    users = [
        {"id": "a", "name": "alice", "console_access": True, "mfa_enabled": False},
        {"id": "b", "name": "bob", "console_access": True, "mfa_enabled": True},
        {"id": "c", "name": "ci-bot", "console_access": False, "mfa_enabled": False},
    ]
    assert flagged(inv(iam_users=users), "CG-AWS-IAM-002") == ["alice"]


def test_unknown_mfa_state_is_skipped():
    users = [
        {"id": "a", "name": "alice", "console_access": True},  # mfa not collected
        {"id": "b", "name": "bob", "mfa_enabled": False},  # console not collected
    ]
    assert flagged(inv(iam_users=users), "CG-AWS-IAM-002") == []


# --------------------------------------------------------------- IAM-003 wildcard admin


def policy(name, statement):
    return {"id": name, "name": name, "document": {"Version": "2012-10-17", "Statement": statement}}


def test_wildcard_admin_policy_is_flagged():
    admin = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    listed = {"Effect": "Allow", "Action": ["s3:GetObject", "*"], "Resource": ["*"]}
    policies = [policy("admin", admin), policy("listed", [listed])]
    assert flagged(inv(iam_policies=policies), "CG-AWS-IAM-003") == ["admin", "listed"]


def test_scoped_deny_and_unknown_policies_are_not_flagged():
    policies = [
        policy("s3-wide", {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}),
        policy("scoped", {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::x"}),
        policy("deny", {"Effect": "Deny", "Action": "*", "Resource": "*"}),
        policy("unknown", {"Effect": "Allow", "Action": "<unknown>", "Resource": "*"}),
        {"id": "broken", "name": "broken", "document": "not a dict"},
    ]
    assert flagged(inv(iam_policies=policies), "CG-AWS-IAM-003") == []


def test_one_finding_per_policy():
    admin = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    assert flagged(inv(iam_policies=[policy("two", [admin, admin])]), "CG-AWS-IAM-003") == ["two"]


# ---------------------------------------------------------------- IAM-004 key rotation


def user(name, created, status="Active"):
    key = {"id": "AKIAEXAMPLE", "status": status, "created": created}
    return {"id": name, "name": name, "access_keys": [key]}


def test_old_active_key_is_flagged_and_boundary_is_90_days():
    users = [
        user("old", days_ago(200)),
        user("edge", days_ago(90)),
        user("over", days_ago(92)),
        user("fresh", days_ago(5)),
    ]
    assert flagged(inv(iam_users=users), "CG-AWS-IAM-004") == ["old", "over"]


def test_inactive_or_unparseable_keys_are_not_flagged():
    users = [
        user("off", days_ago(500), status="Inactive"),
        user("junk", "nope"),
        {"id": "c", "name": "nokeys"},
    ]
    assert flagged(inv(iam_users=users), "CG-AWS-IAM-004") == []


def test_zulu_timestamps_are_understood():
    old = (datetime.now(timezone.utc) - timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert flagged(inv(iam_users=[user("z", old)]), "CG-AWS-IAM-004") == ["z"]
