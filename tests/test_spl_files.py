
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DETECTIONS_DIR = ROOT / "detections"


def test_spl_detection_files_exist():
    files = sorted(DETECTIONS_DIR.rglob("*.spl"))

    assert files, "No .spl detection files found"
    assert len(files) >= 5, (
        f"Expected at least 5 SPL files, found {len(files)}"
    )


def test_spl_detection_files_are_not_empty():
    files = sorted(DETECTIONS_DIR.rglob("*.spl"))

    assert files, "No .spl detection files found"

    for path in files:
        content = path.read_text(encoding="utf-8-sig").strip()

        assert content, f"Empty detection file: {path.name}"
        assert not content.startswith("TODO:"), (
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
