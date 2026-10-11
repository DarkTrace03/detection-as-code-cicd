
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "sysmon" / "whoami_events.json"


def load_cases():
    with FIXTURE.open("r", encoding="utf-8") as file:
        return json.load(file)


def matches_whoami(event):
    """
    Mô phỏng điều kiện lọc của whoami_execution.spl.

    Lưu ý: đây là mô phỏng logic, không phải Splunk SPL engine.
    """
    if str(event.get("EventCode", "")) != "1":
        return False

    image = str(event.get("Image", "")).lower()
    original_filename = str(event.get("OriginalFileName", "")).lower()

    return (
        image.endswith("\\whoami.exe")
        or original_filename == "whoami.exe"
    )


@pytest.mark.parametrize("case", load_cases(), ids=lambda case: case["case"])
def test_whoami_detection_logic(case):
    actual = matches_whoami(case["event"])

    assert actual is case["expected_match"], (
        f"Case: {case['case']}; "
        f"expected={case['expected_match']}, actual={actual}"
    )
