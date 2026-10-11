
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DETECTIONS_DIR = ROOT / "detections"

# Các điều kiện cốt lõi cần được giữ lại trong từng detection.
# Đây là kiểm tra nội dung, không phải trình phân tích cú pháp SPL.
REQUIRED_RULE_CONTENT = {
    "active-directory/kerberoasting.spl": [
        "EventCode=4769",
        "Failure_Code=0x0",
        "Service_Name",
        "krbtgt",
        "Ticket_Encryption_Type",
    ],
    "active-directory/potential_dcsync.spl": [
        "EventCode=4662",
        "Access_Mask=0x100",
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
        "89e95b76-444d-4c62-991a-0facbeda640c",
        "target_account",
    ],
    "active-directory/smb_network_share_access_5140.spl": [
        "EventCode=5140",
        "ADMIN$",
        "C$",
        "IPC$",
        "SMB-Staging",
        "Source_Address",
        "Share_Name",
    ],
    "sysmon/whoami_execution.spl": [
        "EventCode=1",
        "whoami.exe",
        "OriginalFileName",
        "CommandLine",
        "ParentImage",
    ],
    "threat-intelligence/opencti_malicious_dns_query.spl": [
        "EventCode=22",
        "QueryName",
        "opencti:indicator",
        "domain-name",
        "ioc_confidence",
        "ioc_score",
        "severity",
    ],
}


def load_rule(relative_path: str) -> str:
    """Read a detection SPL file using its repository-relative path."""
    path = DETECTIONS_DIR / relative_path

    assert path.is_file(), f"Missing detection file: {relative_path}"

    return path.read_text(encoding="utf-8-sig").strip()


def normalize(content: str) -> str:
    """Normalize whitespace for stable content checks."""
    return " ".join(content.lower().split())


def test_spl_detection_files_exist():
    files = sorted(DETECTIONS_DIR.rglob("*.spl"))

    assert files, "No .spl detection files found"
    assert len(files) >= 5, (
        f"Expected at least 5 SPL files, found {len(files)}"
    )


def test_all_spl_files_are_nonempty_and_not_placeholders():
    files = sorted(DETECTIONS_DIR.rglob("*.spl"))

    assert files, "No .spl detection files found"

    for path in files:
        content = path.read_text(encoding="utf-8-sig").strip()

        assert content, f"Empty detection file: {path.name}"
        assert not content.lower().startswith("todo:"), (
            f"Detection still contains a TODO placeholder: {path.name}"
        )


def test_expected_detection_groups_exist():
    expected = [
        DETECTIONS_DIR / "active-directory",
        DETECTIONS_DIR / "sysmon",
        DETECTIONS_DIR / "threat-intelligence",
    ]

    for directory in expected:
        assert directory.is_dir(), (
            f"Missing detection group: {directory.relative_to(ROOT)}"
        )


@pytest.mark.parametrize(
    "relative_path",
    list(REQUIRED_RULE_CONTENT.keys()),
)
def test_each_detection_contains_required_conditions(relative_path):
    content = normalize(load_rule(relative_path))

    for required in REQUIRED_RULE_CONTENT[relative_path]:
        assert required.lower() in content, (
            f"{relative_path} is missing required content: {required}"
        )


@pytest.mark.parametrize(
    "relative_path",
    list(REQUIRED_RULE_CONTENT.keys()),
)
def test_each_detection_has_a_search_head(relative_path):
    content = load_rule(relative_path)

    # A basic SPL query should have a search command before its first pipe.
    search_head = content.split("|", maxsplit=1)[0].strip()

    assert search_head, (
        f"{relative_path} has no search expression before the first pipe"
    )


@pytest.mark.parametrize(
    "relative_path",
    list(REQUIRED_RULE_CONTENT.keys()),
)
def test_each_detection_contains_a_pipeline(relative_path):
    content = load_rule(relative_path)

    assert "|" in content, (
        f"{relative_path} has no SPL pipeline commands"
    )


def test_dcsync_checks_all_three_replication_rights():
    content = normalize(
        load_rule("active-directory/potential_dcsync.spl")
    )

    replication_guids = [
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
        "89e95b76-444d-4c62-991a-0facbeda640c",
    ]

    for guid in replication_guids:
        assert guid in content, (
            f"DCSync detection is missing replication GUID: {guid}"
        )


def test_whoami_detection_checks_both_image_fields():
    content = normalize(load_rule("sysmon/whoami_execution.spl"))

    assert "image=" in content
    assert "whoami.exe" in content
    assert 'originalfilename="whoami.exe"' in content
    assert " or " in content


def test_opencti_detection_joins_dns_queries_to_domain_indicators():
    content = normalize(
        load_rule("threat-intelligence/opencti_malicious_dns_query.spl")
    )

    assert "join type=inner query" in content
    assert 'sourcetype="opencti:indicator"' in content
    assert 'type="domain-name"' in content
    assert "by query" in content


def test_smb_detection_includes_administrative_shares():
    content = normalize(
        load_rule("active-directory/smb_network_share_access_5140.spl")
    )

    for share in ("admin$", "c$", "d$", "ipc$", "smb-staging"):
        assert share in content, (
            f"SMB detection is missing share condition: {share}"
        )
