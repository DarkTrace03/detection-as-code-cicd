
import unittest
from unittest.mock import Mock


def rollback_saved_search(
    api_request,
    entity_url,
    namespace_url,
    name,
    username,
    password,
    existing,
):
    """Mô phỏng logic rollback, không gọi API thật trong unit test."""
    if existing is None:
        delete_url = f"{namespace_url}/{name}"
        status, _ = api_request(
            delete_url,
            username,
            password,
            method="DELETE",
        )
        if status not in (200, 204):
            raise RuntimeError("rollback failed")
        return "deleted"

    previous_spl = existing.get("content", {}).get("search")
    if previous_spl is None:
        raise RuntimeError("backup lacks previous SPL")

    from urllib.parse import urlencode

    payload = urlencode({"search": previous_spl}).encode("utf-8")
    status, _ = api_request(
        entity_url,
        username,
        password,
        method="POST",
        data=payload,
    )
    if status not in (200, 201):
        raise RuntimeError("rollback failed")

    return "restored"


class TestRollbackLogic(unittest.TestCase):
    def setUp(self):
        self.api = Mock(return_value=(200, "{}"))
        self.entity_url = "https://splunk.example/services/saved/searches/test"
        self.namespace_url = "https://splunk.example/services/saved/searches"
        self.name = "CI_CD_Test_Whoami_Execution"

    def test_existing_search_restores_previous_spl(self):
        existing = {
            "content": {
                "search": "index=main | stats count",
            }
        }

        result = rollback_saved_search(
            self.api,
            self.entity_url,
            self.namespace_url,
            self.name,
            "unit_test",
            "not-a-real-password",
            existing,
        )

        self.assertEqual(result, "restored")
        kwargs = self.api.call_args.kwargs
        self.assertEqual(kwargs["method"], "POST")
        self.assertIn(b"index%3Dmain", kwargs["data"])

    def test_new_search_is_deleted(self):
        result = rollback_saved_search(
            self.api,
            self.entity_url,
            self.namespace_url,
            self.name,
            "unit_test",
            "not-a-real-password",
            None,
        )

        self.assertEqual(result, "deleted")
        self.assertEqual(
            self.api.call_args.kwargs["method"],
            "DELETE",
        )

    def test_missing_previous_spl_fails_safely(self):
        with self.assertRaisesRegex(
            RuntimeError,
            "lacks previous SPL",
        ):
            rollback_saved_search(
                self.api,
                self.entity_url,
                self.namespace_url,
                self.name,
                "unit_test",
                "not-a-real-password",
                {"content": {}},
            )

        self.api.assert_not_called()

    def test_failed_rollback_is_reported(self):
        self.api.return_value = (500, "{}")

        with self.assertRaisesRegex(RuntimeError, "rollback failed"):
            rollback_saved_search(
                self.api,
                self.entity_url,
                self.namespace_url,
                self.name,
                "unit_test",
                "not-a-real-password",
                None,
            )


if __name__ == "__main__":
    unittest.main()
