from pathlib import Path
import re
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]
RULE_DIR = ROOT / "rules"
REQUIRED = {"title", "id", "logsource", "detection"}
MITRE_TECHNIQUE = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$", re.IGNORECASE)

def main() -> int:
    rule_files = sorted(RULE_DIR.rglob("*.yml")) + sorted(RULE_DIR.rglob("*.yaml"))
    if not rule_files:
        print("ERROR: no Sigma YAML rules found")
        return 1

    errors = []
    for path in rule_files:
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:
            errors.append(f"{path.relative_to(ROOT)}: invalid YAML: {exc}")
            continue

        if not isinstance(rule, dict):
            errors.append(f"{path.relative_to(ROOT)}: rule must be a YAML mapping")
            continue

        missing = REQUIRED - set(rule)
        if missing:
            errors.append(f"{path.relative_to(ROOT)}: missing required keys: {', '.join(sorted(missing))}")
            continue

        if not isinstance(rule.get("detection"), dict) or "condition" not in rule["detection"]:
            errors.append(f"{path.relative_to(ROOT)}: detection.condition is required")

        tags = rule.get("tags", [])
        if not isinstance(tags, list):
            errors.append(f"{path.relative_to(ROOT)}: tags must be a list")
        elif not any(MITRE_TECHNIQUE.match(str(tag)) for tag in tags):
            errors.append(f"{path.relative_to(ROOT)}: expected at least one MITRE technique tag like attack.t1059.001")

        if not re.fullmatch(r"[0-9a-fA-F-]{36}", str(rule.get("id", ""))):
            errors.append(f"{path.relative_to(ROOT)}: id should be a UUID")

        if not rule.get("title"):
            errors.append(f"{path.relative_to(ROOT)}: title must not be empty")

        if not isinstance(rule.get("logsource"), dict) or not rule["logsource"]:
            errors.append(f"{path.relative_to(ROOT)}: logsource must be a non-empty mapping")

        if not isinstance(rule.get("detection"), dict) or len(rule["detection"]) < 2:
            errors.append(f"{path.relative_to(ROOT)}: detection should contain selection(s) and condition")

    if errors:
        print("Rule validation FAILED:")
        for error in errors:
            print(f" - {error}")
        return 1

    print(f"Rule validation PASSED: {len(rule_files)} rule(s)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
