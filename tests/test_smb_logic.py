
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "windows" / "smb_5140_events.json"

SENSITIVE_SHARES = (
    "ADMIN$",
    "C$",
    "D$",
    "IPC$",
    "SMB-Staging",
)


def load_cases():
    with FIXTURE.open("r", encoding="utf-8") as file:
        return json.load(file)


def matches_smb_detection(event):
    """Mô phỏng điều kiện lọc trong smb_network_share_access_5140.spl."""
    if str(event.get("EventCode", "")) != "5140":
        return False

    share_name = str(event.get("Share_Name", "")).lower()
    account_name = str(event.get("Account_Name", ""))

    share_matches = any(
        share.lower() in share_name
        for share in SENSITIVE_SHARES
    )
    machine_account = account_name.endswith("$")

    return share_matches and not machine_account


@pytest.mark.parametrize("case", load_cases(), ids=lambda case: case["case"])
def test_smb_detection_logic(case):
    actual = matches_smb_detection(case["event"])

    assert actual is case["expected_match"], (
        f"Case: {case['case']}; "
        f"expected={case['expected_match']}, actual={actual}"
    )
