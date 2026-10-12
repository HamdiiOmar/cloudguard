import json

import pytest
from conftest import make_inventory

from cloudguard.engine import run_scan
from cloudguard.models import Inventory, Severity
from cloudguard.registry import all_checks, check
from cloudguard.reporters import REPORTERS


def test_sample_inventory_expected_findings(sample_inventory):
    result = run_scan(sample_inventory)
    by_check = {}
    for f in result.findings:
        by_check.setdefault(f.check_id, set()).add(f.resource_name)

    assert by_check == {
        "CG-AZ-STG-001": {"stproddata001"},
        "CG-AZ-STG-002": {"stlegacyhttp"},
        "CG-AZ-STG-003": {"stproddata001"},
        "CG-AZ-STG-004": {"stproddata001"},
        "CG-AZ-NET-001": {"nsg-web-prod"},
        "CG-AZ-NET-002": {"nsg-web-prod"},
    }
    assert result.errors == []
    assert result.checks_run == 6


def test_findings_sorted_by_severity_desc(sample_inventory):
    severities = [f.severity for f in run_scan(sample_inventory).findings]
    assert severities == sorted(severities, reverse=True)


def test_min_severity_filters(sample_inventory):
    result = run_scan(sample_inventory, min_severity=Severity.HIGH)
    assert result.findings
    assert all(f.severity >= Severity.HIGH for f in result.findings)


def test_only_and_skip(sample_inventory):
    only = run_scan(sample_inventory, only=["cg-az-stg-001"])
    assert {f.check_id for f in only.findings} == {"CG-AZ-STG-001"}
    assert only.checks_run == 1

    skipped = run_scan(sample_inventory, skip=["CG-AZ-STG-001"])
    assert "CG-AZ-STG-001" not in {f.check_id for f in skipped.findings}


def test_broken_check_is_recorded_not_fatal():
    @check(
        id="CG-TEST-BOOM",
        title="boom",
        description="always raises",
        severity=Severity.LOW,
        provider="azure",
        service="test",
    )
    def boom(inventory):
        raise RuntimeError("kaboom")

    try:
        result = run_scan(make_inventory(storage_accounts=[{"name": "a"}]))
        assert any("CG-TEST-BOOM" in e and "kaboom" in e for e in result.errors)
    finally:
        from cloudguard import registry

        registry._REGISTRY.pop("CG-TEST-BOOM", None)


def test_duplicate_check_id_rejected():
    existing = all_checks("azure")[0].meta
    with pytest.raises(ValueError, match="duplicate"):
        check(
            id=existing.id,
            title="x",
            description="x",
            severity=Severity.LOW,
            provider="azure",
            service="x",
        )(lambda inv: [])


def test_unsupported_provider():
    with pytest.raises(ValueError, match="unsupported provider"):
        run_scan(Inventory(provider="nope", scope=""))


def test_severity_parse():
    assert Severity.parse(" High ") is Severity.HIGH
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("urgent")


def test_inventory_roundtrip(tmp_path, sample_inventory):
    path = tmp_path / "inv.json"
    sample_inventory.save(path)
    assert Inventory.load(path) == sample_inventory


def test_json_report(sample_inventory):
    data = json.loads(REPORTERS["json"](run_scan(sample_inventory)))
    assert data["tool"]["name"] == "cloudguard"
    assert len(data["findings"]) == 6
    assert data["summary"]["high"] == 4
    assert data["findings"][0]["severity"] == "high"


def test_console_report_mentions_frameworks(sample_inventory):
    text = REPORTERS["console"](run_scan(sample_inventory))
    assert "CG-AZ-NET-001" in text
    assert "CIS 6.1" in text
    assert "T1021.001" in text


def test_console_report_no_findings():
    text = REPORTERS["console"](run_scan(make_inventory()))
    assert "No findings." in text


def test_sarif_report_structure(sample_inventory):
    sarif = json.loads(REPORTERS["sarif"](run_scan(sample_inventory)))
    assert sarif["version"] == "2.1.0"

    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert len(rule_ids) == len(set(rule_ids))

    assert len(run["results"]) == 6
    for result in run["results"]:
        assert result["ruleId"] in rule_ids
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
        assert result["level"] in {"error", "warning", "note"}
        loc = result["locations"][0]
        assert loc["physicalLocation"]["region"]["startLine"] == 1
        assert loc["logicalLocations"][0]["fullyQualifiedName"].startswith("/subscriptions/")
        assert result["partialFingerprints"]["cloudguard/v1"]


def test_sarif_fingerprints_stable_and_distinct(sample_inventory):
    def prints():
        sarif = json.loads(REPORTERS["sarif"](run_scan(sample_inventory)))
        return [r["partialFingerprints"]["cloudguard/v1"] for r in sarif["runs"][0]["results"]]

    first = prints()
    assert first == prints()
    assert len(set(first)) == len(first)
