import os
import unittest
from app.services.git_connector import GitConnector
from dotenv import load_dotenv
from unittest.mock import patch, Mock
from functools import partial
from tests.constants import *
from tests.helper import *
import logging

from twisted.internet.defer import returnValue

logger = logging.getLogger(__name__)

class TestDeploymentService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load .env only once for the whole test class (faster, less noise)
        load_dotenv()

    def setUp(self):
        # Fresh service and baseline config per tests
        self.services = GitConnector()

    def test_update_branch_name(self):
        """Verifying deploy delivery codelist in preview mode"""
        logger.info("Running test_update_branch_name...")
        with self.assertLogs(level='DEBUG') as cm:
            self.services.update_branch_name("test")
        self.assertEqual(self.services.params['versionDescriptor.version'], "test")
        self.assertIn("Set branch name: test", str(cm.output))
        logger.info("Test test_update_branch_name is passed successfully")

    def test_create_repo_url(self):
        base = f"{self.services.git_domain}/{self.services.git_organization}/{self.services.git_project}/_apis/git/repositories/"
        repo_url = self.services.create_repo_url("testrepo", "basepath")
        self.assertEqual(repo_url, base+"testrepo?api-version=7.0")

        repo_url = self.services.create_repo_url("testrepo", "")
        self.assertEqual(repo_url, "")

        repo_url = self.services.create_repo_url("testrepo", None)
        self.assertEqual(repo_url, "")

        repo_url = self.services.create_repo_url("testrepo", "fetchSingleFile", "path/to/file")
        self.assertEqual(repo_url, base + "testrepo/items?path=path/to/file&api-version=7.0")

        repo_url = self.services.create_repo_url("testrepo", "fetchAllFiles")
        self.assertEqual(repo_url, base + "testrepo/items")

        repo_url = self.services.create_repo_url("testrepo", "fetchSingleFile",)
        self.assertEqual(f"{base}testrepo/items?path=None&api-version=7.0" , repo_url)

        with self.assertRaises(Exception) as cm:
            repo_url = self.services.create_repo_url()
        self.assertEqual(f"GitConnector.create_repo_url() missing 2 required positional arguments: 'repo_name' and 'action_type'", str(cm.exception))

    def test_fetch_repo_id_with_repo_name(self):
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_func_request, node={"id":1})
            id = self.services.fetch_repo_id_with_repo_name("testrepo")
        self.assertEqual(1, id)

        with patch("requests.Session.request") as mq:
            with self.assertRaises(Exception) as cm:
                mq.side_effect = partial(mock_func_request)
                self.services.fetch_repo_id_with_repo_name()
            self.assertIn("GitConnector.fetch_repo_id_with_repo_name() missing 1 required positional argument: 'repo_name'", str(cm.exception))

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='RequestException')
            with self.assertLogs(level="ERROR") as ctx:
                self.services.fetch_repo_id_with_repo_name("testrepo")

            self.assertIn("Error while fetching fetching repo ID for testrepo: 404 Client Error: Not Found'", str(ctx.output))

    def test_read_json_file(self):
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_func_request, node={"id":1})
            data = self.services.read_json_file("testrepo", "")
        self.assertEqual({"id":1}, data)
        self.assertIsInstance(data, dict)

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_func_request, node="Completed")
            res = self.services.read_json_file("testrepo", "", False)
        self.assertEqual("Completed", res)
        self.assertIsInstance(res, str)

    def test_read_csv_file(self):
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_func_request, node="""StudentID,FirstName\nS001,John""")
            res = self.services.read_csv_file("testrepo", "")
        self.assertIsInstance(res, list)
        self.assertIsInstance(res[0], dict)
        self.assertEqual([{'StudentID': 'S001', 'FirstName': 'John'}], res)

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='RequestException')
            with self.assertRaises(Exception) as ctx:
                self.services.read_csv_file("testrepo", "")
            self.assertIn("Failed to read csv file: 404 Client Error: Not Found", str(ctx.exception))

    def test_fetch_file_list_from_dir(self):
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_func_request, node={})
            data = self.services.fetch_file_list_from_dir("testrepo")
        self.assertEqual([], data)
        self.assertIsInstance(data, list)

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_func_request, node={"id":1})
            data = self.services.fetch_file_list_from_dir("testrepo")
        self.assertEqual([], data)
        self.assertIsInstance(data, list)

        with patch("app.services.git_connector.GitConnector.fetch_repo_id_with_repo_name") as rq:
            with patch("requests.Session.request") as mq:
                rq.return_value = 1
                mq.side_effect = partial(mock_excep_request, param='RequestException')
                with self.assertLogs(level="ERROR") as ctx:
                    self.services.fetch_file_list_from_dir("testrepo")
                self.assertIn("Failed to fetch files:", str(ctx.output))

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_func_request, node={"id": 1})
            data = self.services.fetch_file_list_from_dir("testrepo", "")
        self.assertEqual([], data)
        self.assertIsInstance(data, list)

    def test_verify_artifacts_exist(self):
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_func_request, node={"id": 1})
            status, data = self.services.verify_artifacts_exist([], "testrepo")
        self.assertEqual(True, status)
        self.assertEqual(None,data)

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_func_request, node={"id": 1})
            status, data = self.services.verify_artifacts_exist(["path/to/file"], "testrepo")
        self.assertEqual(True, status)
        self.assertEqual(None,data)

        with patch("app.services.git_connector.GitConnector.fetch_repo_id_with_repo_name") as rq:
            with patch("requests.Session.request") as mq:
                mq.side_effect = partial(mock_excep_request, param='HTTPError')
                rq.return_value = 1
                with self.assertLogs(level="ERROR") as ctx:
                    status, data = self.services.verify_artifacts_exist(["path/to/file"], "testrepo")
            self.assertEqual(False, status)
            self.assertIn("Directory not found: path/to/file",str(ctx.output) )

        with patch("app.services.git_connector.GitConnector.fetch_repo_id_with_repo_name") as rq:
            with patch("requests.Session.request") as mq:
                rq.return_value = 1
                mq.side_effect = partial(mock_excep_request, param='RequestException')
                with self.assertLogs(level="ERROR") as ctx:
                    status, data = self.services.verify_artifacts_exist(["path/to/file"], "testrepo")
                self.assertEqual(False, status)
                self.assertIn("Request failed:", str(ctx.output))


if __name__ == "__main__":
    unittest.main()
