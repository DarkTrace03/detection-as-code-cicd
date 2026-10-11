
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "windows" / "opencti_dns_events.json"


def load_cases():
    with FIXTURE.open("r", encoding="utf-8") as file:
        return json.load(file)


def normalize_domain(value):
    return str(value or "").lower().rstrip(".")


def matches_opencti_dns_detection(event):
    """Mô phỏng đối chiếu DNS query với domain IOC."""
    if str(event.get("EventCode", "")) != "22":
        return False

    query = normalize_domain(event.get("QueryName"))
    indicator = normalize_domain(event.get("ioc_value"))

    if not query or not indicator:
        return False

    return query == indicator


@pytest.mark.parametrize("case", load_cases(), ids=lambda case: case["case"])
def test_opencti_dns_detection_logic(case):
    actual = matches_opencti_dns_detection(case["event"])

    assert actual is case["expected_match"], (
        f"Case: {case['case']}; "
        f"expected={case['expected_match']}, actual={actual}"
    )
