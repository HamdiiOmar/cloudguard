from conftest import make_inventory

from cloudguard.engine import run_scan


def _ids(storage_accounts):
    result = run_scan(make_inventory(storage_accounts=storage_accounts))
    return {f.check_id for f in result.findings}


def test_public_blob_access_flagged():
    assert "CG-AZ-STG-001" in _ids([{"name": "a", "allow_blob_public_access": True}])


def test_public_blob_access_disabled_or_unset_not_flagged():
    assert "CG-AZ-STG-001" not in _ids([{"name": "a", "allow_blob_public_access": False}])
    assert "CG-AZ-STG-001" not in _ids([{"name": "a"}])


def test_secure_transfer_disabled_flagged():
    assert "CG-AZ-STG-002" in _ids([{"name": "a", "enable_https_traffic_only": False}])


def test_secure_transfer_enabled_not_flagged():
    assert "CG-AZ-STG-002" not in _ids([{"name": "a", "enable_https_traffic_only": True}])


def test_old_tls_flagged():
    for version in ("TLS1_0", "TLS1_1"):
        assert "CG-AZ-STG-003" in _ids([{"name": "a", "minimum_tls_version": version}])


def test_tls12_not_flagged():
    assert "CG-AZ-STG-003" not in _ids([{"name": "a", "minimum_tls_version": "TLS1_2"}])


def test_default_allow_flagged_case_insensitive():
    for action in ("Allow", "allow"):
        accounts = [{"name": "a", "network_rule_set": {"default_action": action}}]
        assert "CG-AZ-STG-004" in _ids(accounts)


def test_default_deny_not_flagged():
    accounts = [{"name": "a", "network_rule_set": {"default_action": "Deny"}}]
    assert "CG-AZ-STG-004" not in _ids(accounts)


def test_missing_network_rule_set_does_not_crash():
    result = run_scan(make_inventory(storage_accounts=[{"name": "a", "network_rule_set": None}]))
    assert result.errors == []


def test_finding_uses_resource_id_when_present():
    accounts = [{"id": "/subscriptions/s/x", "name": "a", "allow_blob_public_access": True}]
    result = run_scan(make_inventory(storage_accounts=accounts))
    assert result.findings[0].resource_id == "/subscriptions/s/x"
    assert result.findings[0].cis == ("3.7",)
    assert result.findings[0].mitre == ("T1530",)
