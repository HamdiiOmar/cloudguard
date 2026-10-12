from pathlib import Path

import pytest

from cloudguard.models import Inventory

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
SAMPLE = EXAMPLES / "sample_inventory.json"
SAMPLE_AWS = EXAMPLES / "sample_inventory_aws.json"


@pytest.fixture
def sample_inventory() -> Inventory:
    return Inventory.load(SAMPLE)


@pytest.fixture
def sample_path() -> str:
    return str(SAMPLE)


def make_inventory(**resources) -> Inventory:
    return Inventory(provider="azure", scope="sub-1", resources=resources)
