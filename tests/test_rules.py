import json
from pathlib import Path
import re
import yaml

ROOT = Path(__file__).resolve().parents[1]
RULE = ROOT / "rules/windows/proc_creation_suspicious_powershell.yml"
FIXTURES = ROOT / "tests/fixtures"

def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))

def simplified_match(event, rule):
    """
    Evaluator nhỏ cho đúng logic của rule mẫu này:
    Image kết thúc bằng powershell.exe/pwsh.exe AND CommandLine chứa
    một trong các switch encoded. Đây không phải Sigma engine tổng quát.
    """
    detection = rule["detection"]
    image = str(event.get("Image", "")).lower()
    command = str(event.get("CommandLine", "")).lower()

    image_patterns = detection["selection_image"]["Image|endswith"]
    image_match = any(image.endswith(str(value).lower()) for value in image_patterns)

    encoded_patterns = detection["selection_encoded"]["CommandLine|contains"]
    encoded_match = any(str(value).lower() in command for value in encoded_patterns)

    return image_match and encoded_match

def test_rule_has_required_metadata():
    rule = yaml.safe_load(RULE.read_text(encoding="utf-8"))
    assert rule["title"]
    assert rule["id"]
    assert rule["logsource"]["category"] == "process_creation"
    assert "condition" in rule["detection"]
    assert any(re.fullmatch(r"attack\.t\d{4}(?:\.\d{3})?", tag) for tag in rule["tags"])

def test_positive_fixture_matches():
    rule = yaml.safe_load(RULE.read_text(encoding="utf-8"))
    event = load_json(FIXTURES / "powershell_positive.json")
    assert simplified_match(event, rule)

def test_negative_fixture_does_not_match():
    rule = yaml.safe_load(RULE.read_text(encoding="utf-8"))
    event = load_json(FIXTURES / "powershell_negative.json")
    assert not simplified_match(event, rule)
