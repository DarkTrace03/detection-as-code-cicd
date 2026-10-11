
import unittest
from unittest.mock import Mock
from urllib.parse import unquote_plus

from scripts.deploy_splunk_saved_search import (
    DeploymentError,
    rollback_saved_search,
)


class TestRollbackLogic(unittest.TestCase):
    def setUp(self):
        self.api = Mock(return_value=(200, "{}"))
        self.entity_url = (
            "https://splunk.example/services/saved/searches/test"
        )
        self.namespace_url = (
            "https://splunk.example/services/saved/searches"
        )
        self.name = "CI_CD_Test_Whoami_Execution"
        self.username = "unit_test"
        self.password = "not-a-real-password"

    def rollback(self, existing):
        return rollback_saved_search(
            api_request=self.api,
            entity_url=self.entity_url,
            namespace_url=self.namespace_url,
            name=self.name,
            username=self.username,
            password=self.password,
            existing=existing,
        )

    def test_existing_search_restores_previous_spl(self):
        previous_spl = "index=main | stats count"
        existing = {"content": {"search": previous_spl}}

        self.rollback(existing)

        args, kwargs = self.api.call_args
        self.assertEqual(args[0], self.entity_url)
        self.assertEqual(kwargs["method"], "POST")
        self.assertEqual(
            unquote_plus(kwargs["data"].decode("utf-8")),
            f"search={previous_spl}",
        )

    def test_new_search_is_deleted(self):
        self.rollback(None)

        args, kwargs = self.api.call_args
        self.assertIn(self.name, args[0])
        self.assertEqual(kwargs["method"], "DELETE")

    def test_missing_previous_spl_fails_safely(self):
        with self.assertRaisesRegex(
            DeploymentError,
            "lacks the previous SPL",
        ):
            self.rollback({"content": {}})

        self.api.assert_not_called()

    def test_failed_rollback_is_reported(self):
        self.api.return_value = (500, "{}")

        with self.assertRaisesRegex(
            DeploymentError,
            "Delete rollback returned HTTP 500",
        ):
            self.rollback(None)

    def test_existing_search_restore_failure_is_reported(self):
        self.api.return_value = (500, "{}")

        with self.assertRaisesRegex(
            DeploymentError,
            "Restore rollback returned HTTP 500",
        ):
            self.rollback({
                "content": {
                    "search": "index=main | stats count",
                }
            })


if __name__ == "__main__":
    unittest.main()
