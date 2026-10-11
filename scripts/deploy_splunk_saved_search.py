import base64
import os
import ssl
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

# Lab-only: intentionally skips TLS certificate verification.
# Replace this with CA verification before production use.
SSL_CONTEXT = ssl._create_unverified_context()

SAVED_SEARCH_NAME = "CI_CD_Test_Whoami_Execution"
DETECTION_FILE = (
    Path(__file__).resolve().parent.parent
    / "detections"
    / "sysmon"
    / "whoami_execution.spl"
)


def main():
    base_url = os.environ["SPLUNK_URL"].rstrip("/")
    username = os.environ["SPLUNK_USERNAME"]
    password = os.environ["SPLUNK_PASSWORD"]

    if not base_url.startswith("https://"):
        raise ValueError("SPLUNK_URL must use HTTPS")

    if not DETECTION_FILE.is_file():
        raise FileNotFoundError(f"Detection file not found: {DETECTION_FILE}")

    search_spl = DETECTION_FILE.read_text(encoding="utf-8").strip()
    if not search_spl:
        raise ValueError("Detection SPL is empty")

    api_base = f"{base_url}/services/saved/searches"
    entity_url = f"{api_base}/{quote(SAVED_SEARCH_NAME, safe='')}"

    token = base64.b64encode(
        f"{username}:{password}".encode("utf-8")
    ).decode("ascii")

    def api_request(url, method="GET", data=None):
        headers = {
            "Authorization": f"Basic {token}",
            "Accept": "application/json",
        }
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        request = Request(
            url,
            data=data,
            headers=headers,
            method=method,
        )

        try:
            with urlopen(
                request,
                context=SSL_CONTEXT,
                timeout=20,
            ) as response:
                return response.status, response.read().decode(
                    "utf-8", errors="replace"
                )
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            if exc.code == 404:
                return 404, body
            # Do not print request headers or credentials.
            print(f"Splunk API returned HTTP {exc.code}", file=sys.stderr)
            print(body[:1500], file=sys.stderr)
            raise
        except URLError as exc:
            print(
                f"Could not connect to Splunk API: {exc.reason}",
                file=sys.stderr,
            )
            raise

    payload = urlencode({
        "name": SAVED_SEARCH_NAME,
        "search": search_spl,
    }).encode("utf-8")

    status, _ = api_request(entity_url)

    if status == 200:
        status, _ = api_request(entity_url, method="POST", data=payload)
        print(f"Updated Saved Search: {SAVED_SEARCH_NAME} (HTTP {status})")
    elif status == 404:
        status, _ = api_request(api_base, method="POST", data=payload)
        print(f"Created Saved Search: {SAVED_SEARCH_NAME} (HTTP {status})")
    else:
        raise RuntimeError(f"Unexpected lookup status: HTTP {status}")

    verify_status, _ = api_request(entity_url)
    if verify_status != 200:
        raise RuntimeError(
            f"Saved Search verification failed: HTTP {verify_status}"
        )

    print("Verification successful: Saved Search is readable.")
    print("Scheduling and alert actions were not configured.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Deployment failed: {exc}", file=sys.stderr)
        sys.exit(1)