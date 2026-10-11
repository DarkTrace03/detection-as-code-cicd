
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = (
    ROOT
    / "tests"
    / "fixtures"
    / "active_directory"
    / "dcsync_events.json"
)

REPLICATION_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
    "89e95b76-444d-4c62-991a-0facbeda640c",
}


def load_cases():
    with FIXTURE.open("r", encoding="utf-8") as file:
        return json.load(file)


def matches_dcsync_detection(event):
    """Mô phỏng các điều kiện lọc trong potential_dcsync.spl."""
    if str(event.get("EventCode", "")) != "4662":
        return False

    if str(event.get("Access_Mask", "")).lower() != "0x100":
        return False

    properties_guid = str(event.get("Properties_GUID", "")).lower()

    if not any(guid in properties_guid for guid in REPLICATION_GUIDS):
        return False

    account_name = str(event.get("Account_Name", ""))

    # Mô phỏng điều kiện loại tài khoản máy và MSOL.
    if account_name.endswith("$"):
        return False

    if account_name.startswith("MSOL_"):
        return False

    return True


@pytest.mark.parametrize("case", load_cases(), ids=lambda case: case["case"])
def test_dcsync_detection_logic(case):
    actual = matches_dcsync_detection(case["event"])

    assert actual is case["expected_match"], (
        f"Case: {case['case']}; "
        f"expected={case['expected_match']}, actual={actual}"
    )
