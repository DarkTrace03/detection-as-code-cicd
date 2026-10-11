
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "deployment-manifest.json"

ALLOWED_DEPLOYMENTS = {
    "test-whoami",
}

REQUIRED_NAMESPACE_FIELDS = {
    "app",
    "owner",
}


class ManifestValidationError(Exception):
    pass


def validate_manifest(manifest, root=ROOT):
    if not isinstance(manifest, dict):
        raise ManifestValidationError(
            "Manifest root must be a JSON object"
        )

    namespace = manifest.get("namespace")
    if not isinstance(namespace, dict):
        raise ManifestValidationError(
            "Manifest must contain a namespace object"
        )

    missing_namespace_fields = (
        REQUIRED_NAMESPACE_FIELDS - namespace.keys()
    )
    if missing_namespace_fields:
        raise ManifestValidationError(
            "Missing namespace fields: "
            + ", ".join(sorted(missing_namespace_fields))
        )

    if not isinstance(namespace["app"], str) or not namespace["app"].strip():
        raise ManifestValidationError(
            "namespace.app must be a non-empty string"
        )

    if not isinstance(namespace["owner"], str) or not namespace["owner"].strip():
        raise ManifestValidationError(
            "namespace.owner must be a non-empty string"
        )

    deployments = manifest.get("deployments")
    if not isinstance(deployments, list) or not deployments:
        raise ManifestValidationError(
            "deployments must be a non-empty list"
        )

    enabled = [
        item for item in deployments
        if isinstance(item, dict) and item.get("enabled") is True
    ]

    if len(enabled) != 1:
        raise ManifestValidationError(
            "Exactly one deployment must be enabled"
        )

    item = enabled[0]

    deployment_id = item.get("id")
    if deployment_id not in ALLOWED_DEPLOYMENTS:
        raise ManifestValidationError(
            f"Deployment ID is not allowlisted: {deployment_id!r}"
        )

    for field in ("source", "saved_search_name"):
        value = item.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ManifestValidationError(
                f"{field} must be a non-empty string"
            )

    for field in ("schedule_enabled", "alert_actions_enabled"):
        if item.get(field) is not False:
            raise ManifestValidationError(
                f"{field} must explicitly be false"
            )

    source_path = Path(item["source"])
    if source_path.is_absolute():
        raise ManifestValidationError(
            "Detection source must use a relative path"
        )

    resolved_root = Path(root).resolve()
    resolved_source = (resolved_root / source_path).resolve()

    if resolved_root not in resolved_source.parents:
        raise ManifestValidationError(
            "Detection source must remain inside the repository"
        )

    if not resolved_source.is_file():
        raise ManifestValidationError(
            f"Detection source does not exist: {item['source']}"
        )

    if not resolved_source.read_text(encoding="utf-8").strip():
        raise ManifestValidationError(
            f"Detection source is empty: {item['source']}"
        )


def main():
    try:
        if not MANIFEST_PATH.is_file():
            raise ManifestValidationError(
                "deployment-manifest.json was not found"
            )

        manifest = json.loads(
            MANIFEST_PATH.read_text(encoding="utf-8")
        )
        validate_manifest(manifest)
        print("Deployment manifest validation passed.")

    except (json.JSONDecodeError, ManifestValidationError) as exc:
        print(f"Manifest validation failed: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
