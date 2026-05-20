import os
import unittest
from app.services.deployment_service import DeploymentService
from app.models.deployment_request import DeploymentRequest
from app.services.translation_service import TranslationService
from dotenv import load_dotenv
from unittest.mock import patch, Mock
from functools import partial
from tests.constants import *
from tests.helper import *
import logging

logger = logging.getLogger(__name__)

class TestDeploymentService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load .env only once for the whole test class (faster, less noise)
        load_dotenv()

    def setUp(self):
        # Fresh service and baseline config per tests
        self.services = DeploymentService()
        self.services.deploy_flag = ''
        self.services.execution_mode = EXECUTION_TYPE[0]
        self.services.env = ENV
        self.services.payload = PAYLOAD
        self.services.metadata = read_test_data(data_type=METADATA_PATH)
        self.services.SFG = read_test_data(data_type=SFG_PATH)
        self.services.CDP = read_git_file(directpath = CDP_PATH, json_type=False)
        self.services.wd = read_git_file(directpath=WD_PATH)
        self.services.rule = read_git_file(directpath=RULE_PATH)
        self.services.request = DeploymentRequest(
            env_name=self.services.payload["env_name"],
            mode=self.services.payload["mode"],
            requested_by=self.services.payload["requested_by"],
            interfaces=self.services.payload["interfaces"],
            branch_name=self.services.payload["branch_name"],
            repo_name=self.services.payload["repo_name"],
        )

    def test_deploy(self):
        """Verifying deploy delivery codelist in preview mode"""
        logger.info("Running test_deploy...")
        with patch("requests.Session.request") as mq:
            with self.assertLogs(level="INFO") as cm:
                mq.side_effect = partial(mock_func_request)
                self.services.deploy(self.services.payload)
            self.assertIn(f"Request status: FAILED", str(cm.output))
            self.assertIn("Deployment prerequisites check failed due to Repository ID not found", str(cm.output))
        logger.info("Test test_deploy is passed successfully")

    def test_deploy_with_invalid_artifacts(self):
        """Verifying deploy delivery codelist with invalid artifacts in preview mode"""
        logger.info("Running test_deploy_with_invalid_artifacts...")
        with patch("app.services.git_connector.GitConnector.verify_artifacts_exist") as gt:
            with self.assertLogs(level="INFO") as cm:
                gt.return_value = True, None
                self.services.deploy(self.services.payload)
            self.assertIn(f"Starting deployment management for {self.services.env} , interface count = {len(self.services.payload['interfaces'])} with interfaces {self.services.payload['interfaces']}", str(cm.output))
            self.assertIn("Failed to read file: 404 Client Error: Not Found for url:", str(cm.output))
        logger.info("Test test_deploy_with_invalid_artifacts is passed successfully")

    def test_deploy_with_artifacts_issue(self):
        """Verifying deploy delivery codelist with failed or exception cases in preview mode"""
        logger.info("Running test_deploy_with_artifacts_issue...")
        with patch("app.services.deployment_service.DeploymentService.check_deployment_prerequisites") as mq:
            with patch("app.services.git_connector.GitConnector.verify_artifacts_exist") as gte:
                with self.assertLogs(level="ERROR") as cm:
                    mq.return_value = None
                    gte.return_value = False, "Artifacts not present"
                    self.services.deploy(self.services.payload)
                self.assertIn(f"Deployment/Removal failed for {INTERFACE_NAME} due to Artifacts not present", str(cm.output))
        logger.info("Test test_deploy_with_artifacts_issue is passed successfully")

    def test_deploy_with_empty_metadata(self):
        """Verifying deploy delivery codelist with metadata as null or no CD artifacts in preview mode"""
        logger.info("Running test_deploy_with_empty_metadata...")
        with patch("app.services.git_connector.GitConnector.verify_artifacts_exist") as mq:
            with self.assertLogs(level="INFO") as cm:
                mq.return_value = True, None
                self.services.git_connector.read_json_file = Mock(return_value={"SourceNode": "null"})
                self.services.deploy(self.services.payload)
            self.assertIn(f"Failed to Deploy artifact for {INTERFACE_NAME} due to Hostname/Node information not found for null in host.json", str(cm.output))
        self.assertIn(f"Skipping deployment", str(cm.output))
        logger.info("Test test_deploy_with_empty_metadata is passed successfully")

    @patch("requests.Session.request")
    @patch("app.services.deployment_service.CDServices.is_rule_exist")
    @patch("app.services.deployment_service.CDServices.is_watch_dir_exist")
    @patch("app.services.git_connector.GitConnector.fetch_file_list_from_dir")
    @patch("app.services.git_connector.GitConnector.read_json_file")
    @patch("app.services.git_connector.GitConnector.verify_artifacts_exist")
    def test_deploy_with_metadata(
            self,
            mq,
            rj,
            gt,
            wd,
            rl,
            rq,
    ):
        """Verify the deploy with meta data for CD and B2bI artifacts completion"""
        with self.assertLogs(level="INFO") as cm:
            mq.return_value = (True, None)
            gt.return_value = []
            wd.return_value = False
            rl.return_value = (False, [])

            rj.side_effect = partial(
                read_git_file,
                wd_data=self.services.wd,
                rule_data=self.services.rule,
                cdp_data=self.services.CDP,
            )

            rq.side_effect = partial(
                mock_func_request,
                node=[{"totalRecords": 0}],
            )

            self.services.deploy(self.services.payload)

        logs = " ".join(cm.output)
        self.assertIn("CD artifacts processing completed.", logs)
        self.assertIn("B2BI artifacts processing completed.", logs)

    @patch("app.services.git_connector.GitConnector.read_json_file")
    def test_get_cd_artifacts_from_repo(self, rj):
        """Verify that this function should return the cdp, watch dir, rule and procname"""
        rj.side_effect = partial(
            read_git_file,
            wd_data=self.services.wd,
            rule_data=self.services.rule,
            cdp_data=self.services.CDP,
        )
        result = self.services.get_cd_artifacts_from_repo(self.services.request, [""], None, [])
        self.assertEqual(len(result), 4)

    def test_process_cd_artifacts_without_source_node(self):
        """Verify that this function should process the cdp and watch dir without source node"""
        with self.assertLogs(level="WARNING") as cm:
            self.services.process_cd_artifacts(self.services.payload,self.services.request, [""], None, None)
        self.assertIn("Source node not found or null/Empty : None", str(cm.output))

    def test_process_cd_artifacts_without_host_data(self):
        """Verify that this function should process the cdp and watch dir without host data"""

        with self.assertRaises(Exception) as cm:
            self.services.translate_service = TranslationService(self.services.payload.get('deploy_config'))
            temp = self.services.payload["hosts"]
            self.services.payload["hosts"] = {"hosts":[]}
            self.services.process_cd_artifacts(self.services.payload,self.services.request, [""], "TEST", None)
            self.services.payload["hosts"] = temp
        self.assertIn("Hostname not found for TEST in host.json", str(cm.exception))

        with self.assertRaises(Exception) as cm:
            self.services.translate_service = TranslationService(self.services.payload.get('deploy_config'))
            temp = self.services.payload["hosts"]
            temp["hosts"] = {'hosts': [{'hostname': 'mullet.sobeys.com', 'nodename': 'EDWCMA01', 'os': None, 'password': 'default'}]}
            self.services.process_cd_artifacts(temp,self.services.request, [""], "EDWCMA01", None)
        self.assertIn("OS not found for EDWCMA01 in host.json", str(cm.exception))

        with self.assertRaises(Exception) as cm:
            self.services.translate_service = TranslationService(self.services.payload.get('deploy_config'))
            temp = self.services.payload["hosts"]
            temp["hosts"] = {'hosts': [{'hostname': 'mullet.sobeys.com', 'nodename': 'EDWCMA01', 'os': "unix", 'password': None}]}
            self.services.process_cd_artifacts(temp,self.services.request, [""], "EDWCMA01", None)
        self.assertIn("Credential not found for EDWCMA01 in host.json", str(cm.exception))

    def test_fetch_codelist(self):
        """Verify fetch codelist function with codelist data"""
        with self.assertRaises(Exception) as cm:
            self.services.fetch_codelist(None, None)
        self.assertIn("Failed to fetch codelist from None", str(cm.exception))

        with patch("app.services.git_connector.GitConnector.read_json_file") as rj:
            rj.side_effect = partial(
                read_git_file,
                wd_data=self.services.wd,
                rule_data=self.services.rule,
                cdp_data=self.services.CDP,
            )
            self.services.translate_service = TranslationService(self.services.payload.get('deploy_config'))
            result = self.services.fetch_codelist(self.services.payload["repo_name"], CD_FILES[0])
            self.assertTrue(type(result), dict)

    @patch("app.services.deployment_service.DeploymentService.fetch_codelist")
    @patch("app.services.git_connector.GitConnector.fetch_file_list_from_dir")
    def test_fetch_all_codelist_entry(self, fetch, codelist):
        """Verify fetch codelist function with codelist data"""
        fetch.return_value = CODELISTS
        codelist.return_value = {}
        b2bi_obj = self.services.fetch_all_codelist_entry(None, self.services.request)
        self.assertTrue(isinstance(b2bi_obj, object))
        self.assertEqual(b2bi_obj.identify_consumer, [{}])
        self.assertEqual(b2bi_obj.delivery_cd, [{}])
        self.assertEqual(b2bi_obj.delivery_gen, [{}])
        self.assertEqual(b2bi_obj.delivery_wsmq, [{}])
        self.assertEqual(b2bi_obj.delivery_email, [{}])

    @patch("requests.Session.request")
    @patch("app.services.git_connector.GitConnector.fetch_file_list_from_dir")
    @patch("app.services.git_connector.GitConnector.read_json_file")
    @patch("app.services.git_connector.GitConnector.verify_artifacts_exist")
    def test_deploy_with_b2bi_data_only(
            self,
            mq,
            rj,
            gt,
            rq
    ):
        """Verify deploy with b2bi data only"""
        with self.assertLogs(level="INFO") as cm:
            mq.return_value = (True, None)
            gt.return_value = []
            rj.return_value = {"SourceNode": ""}
            rq.side_effect = partial(
                mock_func_request,
                node=[{"totalRecords": 0}],
            )
            self.services.deploy(self.services.payload)

        logs = " ".join(cm.output)
        self.assertNotIn("CD artifacts processing completed.", logs)
        self.assertIn("B2BI artifacts processing completed.", logs)

if __name__ == "__main__":
    unittest.main()
