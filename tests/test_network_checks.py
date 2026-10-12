import pytest
from conftest import make_inventory

from cloudguard.engine import run_scan
from cloudguard.providers.azure.checks.network import _port_matches, internet_allow_rules


def _rule(**overrides):
    rule = {
        "name": "r",
        "priority": 100,
        "direction": "Inbound",
        "access": "Allow",
        "protocol": "Tcp",
        "source_address_prefix": "*",
        "destination_port_range": "3389",
    }
    rule.update(overrides)
    return rule


def _ids(*rules):
    nsg = {"name": "nsg", "security_rules": list(rules)}
    result = run_scan(make_inventory(network_security_groups=[nsg]))
    return {f.check_id for f in result.findings}


@pytest.mark.parametrize(
    ("spec", "port", "expected"),
    [
        ("*", 22, True),
        ("22", 22, True),
        ("22", 23, False),
        ("20-30", 22, True),
        ("23-30", 22, False),
        ("abc", 22, False),
        ("", 22, False),
    ],
)
def test_port_matches(spec, port, expected):
    assert _port_matches(spec, port) is expected


def test_rdp_from_any_flagged():
    assert "CG-AZ-NET-001" in _ids(_rule())


def test_ssh_from_internet_tag_with_port_list_flagged():
    rule = _rule(
        source_address_prefix="Internet",
        destination_port_range=None,
        destination_port_ranges=["22", "8080"],
    )
    assert "CG-AZ-NET-002" in _ids(rule)


def test_wildcard_port_exposes_both():
    assert {"CG-AZ-NET-001", "CG-AZ-NET-002"} <= _ids(_rule(destination_port_range="*"))


def test_port_range_covering_rdp_flagged():
    assert "CG-AZ-NET-001" in _ids(_rule(destination_port_range="3000-4000"))


def test_restricted_source_not_flagged():
    assert "CG-AZ-NET-001" not in _ids(_rule(source_address_prefix="10.0.0.0/24"))


def test_source_prefix_list_containing_internet_flagged():
    rule = _rule(source_address_prefix=None, source_address_prefixes=["10.0.0.0/8", "0.0.0.0/0"])
    assert "CG-AZ-NET-001" in _ids(rule)


def test_udp_not_flagged():
    assert "CG-AZ-NET-001" not in _ids(_rule(protocol="Udp"))


def test_outbound_not_flagged():
    assert "CG-AZ-NET-001" not in _ids(_rule(direction="Outbound"))


def test_deny_rule_not_flagged():
    assert "CG-AZ-NET-001" not in _ids(_rule(access="Deny"))


def test_lower_priority_number_deny_shadows_allow():
    deny = _rule(name="deny", priority=100, access="Deny")
    allow = _rule(name="allow", priority=200)
    assert internet_allow_rules({"security_rules": [allow, deny]}, 3389) == []


def test_higher_priority_allow_wins_over_later_deny():
    allow = _rule(name="allow", priority=100)
    deny = _rule(name="deny", priority=200, access="Deny")
    rules = internet_allow_rules({"security_rules": [deny, allow]}, 3389)
    assert [r["name"] for r in rules] == ["allow"]


def test_nsg_without_rules_is_fine():
    result = run_scan(make_inventory(network_security_groups=[{"name": "empty"}]))
    assert result.findings == []
    assert result.errors == []
