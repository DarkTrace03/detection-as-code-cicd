
import base64
import json
import os
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


# LAB ONLY: TLS certificate verification is intentionally disabled.
# Do not use this setting in production.
SSL_CONTEXT = ssl._create_unverified_context()

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "deployment-manifest.json"
BACKUP_DIR = ROOT / "backups"

# Fail closed: only this deployment target is permitted for this phase.
ALLOWED_DEPLOYMENTS = {"test-whoami"}


class DeploymentError(RuntimeError):
    pass


def api_request(url, username, password, method="GET", data=None):
    token = base64.b64encode(
        f"{username}:{password}".encode("utf-8")
    ).decode("ascii")

    headers = {
        "Authorization": f"Basic {token}",
        "Accept": "application/json",
    }
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    request = Request(url, data=data, headers=headers, method=method)

    try:
        with urlopen(request, context=SSL_CONTEXT, timeout=30) as response:
            return response.status, response.read().decode(
                "utf-8", errors="replace"
            )
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        if exc.code == 404:
            return 404, body

        # Never print request headers or credentials.
        print(f"Splunk API returned HTTP {exc.code}", file=sys.stderr)
        print(body[:1200], file=sys.stderr)
        raise DeploymentError(
            f"Splunk API request failed: HTTP {exc.code}"
        ) from None
    except URLError as exc:
        print(
            f"Splunk API connection failed: {exc.reason}",
            file=sys.stderr,
        )
        raise DeploymentError(
            "Could not connect to Splunk REST API"
        ) from None


def parse_entry(body):
    try:
        data = json.loads(body)
        entries = data.get("entry", [])
        return entries[0] if entries else None
    except (json.JSONDecodeError, AttributeError):
        raise DeploymentError(
            "Splunk returned an unexpected JSON response"
        ) from None


def rollback_saved_search(
    api_request,
    entity_url,
    namespace_url,
    name,
    username,
    password,
    existing,
):
    """
    Roll back a Saved Search using the supplied API client.

    If the Saved Search did not exist before deployment, delete the
    newly created object. Otherwise, restore its previous SPL.

    This function does not restore the complete configuration or ACL.
    """
    if existing is None:
        delete_url = (
            f"{namespace_url}/{quote(name, safe='')}"
        )
        status, _ = api_request(
            delete_url,
            username,
            password,
            method="DELETE",
        )

        if status not in (200, 204):
            raise DeploymentError(
                f"Delete rollback returned HTTP {status}"
            )

        print(
            "Rollback successful: removed newly created Saved Search."
        )
        return

    previous_spl = existing.get("content", {}).get("search")
    if previous_spl is None:
        raise DeploymentError(
            "Backup lacks the previous SPL; cannot safely rollback"
        )

    rollback_payload = urlencode({
        "search": previous_spl,
    }).encode("utf-8")

    status, _ = api_request(
        entity_url,
        username,
        password,
        method="POST",
        data=rollback_payload,
    )

    if status not in (200, 201):
        raise DeploymentError(
            f"Restore rollback returned HTTP {status}"
        )

    print("Rollback request accepted: previous SPL restored.")


def main():
    base_url = os.environ["SPLUNK_URL"].rstrip("/")
    username = os.environ["SPLUNK_USERNAME"]
    password = os.environ["SPLUNK_PASSWORD"]

    if not base_url.startswith("https://"):
        raise DeploymentError("SPLUNK_URL must use HTTPS")

    if not MANIFEST_PATH.is_file():
        raise DeploymentError(
            "deployment-manifest.json was not found"
        )

    manifest = json.loads(
        MANIFEST_PATH.read_text(encoding="utf-8")
    )
    namespace = manifest.get("namespace", {})
    owner = namespace.get("owner")
    app = namespace.get("app")

    if not owner or not app:
        raise DeploymentError(
            "Manifest must specify namespace owner and app"
        )

    deployments = [
        item
        for item in manifest.get("deployments", [])
        if item.get("enabled") is True
    ]

    if not deployments:
        raise DeploymentError(
            "Manifest contains no enabled deployments"
        )

    if len(deployments) != 1:
        raise DeploymentError(
            "This rollout supports exactly one enabled deployment"
        )

    item = deployments[0]
    deployment_id = item.get("id")

    if deployment_id not in ALLOWED_DEPLOYMENTS:
        raise DeploymentError(
            "Deployment ID is not in the script allowlist"
        )

    if item.get("schedule_enabled") is not False:
        raise DeploymentError(
            "Scheduled execution must remain disabled"
        )

    if item.get("alert_actions_enabled") is not False:
        raise DeploymentError(
            "Alert actions must remain disabled"
        )

    source = (ROOT / item["source"]).resolve()

    if ROOT.resolve() not in source.parents:
        raise DeploymentError(
            "Detection source must be inside the repository"
        )

    if not source.is_file():
        raise DeploymentError(
            f"Detection source not found: {item['source']}"
        )

    desired_spl = source.read_text(
        encoding="utf-8"
    ).strip()

    if not desired_spl:
        raise DeploymentError("Detection SPL is empty")

    name = item["saved_search_name"]

    namespace_url = (
        f"{base_url}/servicesNS/{quote(owner, safe='')}/"
        f"{quote(app, safe='')}/saved/searches"
    )
    entity_url = (
        f"{namespace_url}/{quote(name, safe='')}?output_mode=json"
    )
    collection_url = f"{namespace_url}?output_mode=json"

    status, body = api_request(
        entity_url,
        username,
        password,
    )

    existing = parse_entry(body) if status == 200 else None

    if status not in (200, 404):
        raise DeploymentError(
            f"Unexpected lookup status: HTTP {status}"
        )

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    backup_path = (
        BACKUP_DIR / f"{deployment_id}-{timestamp}.json"
    )

    backup = {
        "timestamp_utc": timestamp,
        "deployment_id": deployment_id,
        "saved_search_name": name,
        "namespace": {
            "owner": owner,
            "app": app,
        },
        "existed_before_deploy": existing is not None,
        "previous_content": (
            existing.get("content", {}) if existing else None
        ),
        "previous_acl": (
            existing.get("acl", {}) if existing else None
        ),
    }

    backup_path.write_text(
        json.dumps(
            backup,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    print(f"Backup created: {backup_path.name}")

    mutated = False

    try:
        fields = {
            "search": desired_spl,
            "description": item.get("description", ""),
        }

        if existing is None:
            fields["name"] = name
            target_url = collection_url
        else:
            target_url = entity_url

        payload = urlencode(fields).encode("utf-8")

        deploy_status, _ = api_request(
            target_url,
            username,
            password,
            method="POST",
            data=payload,
        )

        if deploy_status not in (200, 201):
            raise DeploymentError(
                "Unexpected deployment status: "
                f"HTTP {deploy_status}"
            )

        mutated = True
        print(
            f"Deployment request accepted: HTTP {deploy_status}"
        )

        verify_status, verify_body = api_request(
            entity_url,
            username,
            password,
        )

        verified = (
            parse_entry(verify_body)
            if verify_status == 200
            else None
        )

        actual_spl = (
            verified.get("content", {}).get("search", "").strip()
            if verified
            else ""
        )

        if not verified or actual_spl != desired_spl:
            raise DeploymentError(
                "Post-deployment SPL verification failed"
            )

        print(f"Verification successful: {name}")
        print(
            "Scheduling and alert actions were not enabled."
        )

    except Exception as deploy_error:
        if not mutated:
            raise

        print(
            "Deployment verification failed; attempting rollback."
        )

        try:
            rollback_saved_search(
                api_request=api_request,
                entity_url=entity_url,
                namespace_url=namespace_url,
                name=name,
                username=username,
                password=password,
                existing=existing,
            )
        except Exception:
            print(
                "CRITICAL: Automatic rollback failed. "
                "Inspect Splunk and the backup artifact immediately.",
                file=sys.stderr,
            )
            raise DeploymentError(
                "Deployment failed and rollback failed"
            ) from None

        raise DeploymentError(
            "Deployment failed; rollback attempted. "
            f"Cause: {deploy_error}"
        ) from None


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Deployment failed: {exc}", file=sys.stderr)
        sys.exit(1)
