
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = (
    ROOT
    / "tests"
    / "fixtures"
    / "active_directory"
    / "kerberoasting_events.json"
)


def load_cases():
    with FIXTURE.open("r", encoding="utf-8") as file:
        return json.load(file)


def matches_kerberoasting(event):
    """Mô phỏng điều kiện lọc của kerberoasting.spl."""
    if str(event.get("EventCode", "")) != "4769":
        return False

    if str(event.get("Failure_Code", "")).lower() != "0x0":
        return False

    account_name = str(event.get("Account_Name", ""))
    service_name = str(event.get("Service_Name", ""))

    # Mô phỏng: where NOT match(Account_Name, "\$@")
    if account_name.endswith("$@"):
        return False

    # Mô phỏng: where Service_Name!="krbtgt"
    if service_name == "krbtgt":
        return False

    # Mô phỏng: where NOT match(Service_Name, "\$$")
    if service_name.endswith("$"):
        return False

    return True


@pytest.mark.parametrize("case", load_cases(), ids=lambda case: case["case"])
def test_kerberoasting_detection_logic(case):
    actual = matches_kerberoasting(case["event"])

    assert actual is case["expected_match"], (
        f"Case: {case['case']}; "
        f"expected={case['expected_match']}, actual={actual}"
    )
