import unittest
from app.services.cd_service import CDServices
from dotenv import load_dotenv
from unittest.mock import patch, MagicMock
from functools import partial
import copy
import json
from tests.constants import *
from tests.helper import *
import  logging

from twisted.internet.defer import returnValue

logger = logging.getLogger(__name__)

class TestCDService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load .env only once for the whole test class (faster, less noise)
        load_dotenv()

    def setUp(self):
        # Fresh service and baseline config per tests
        self.services = CDServices()
        self.services.base_url = "http://dummy.com:8080"
        self.get_rules = read_test_data("GET_RULES_LIST")
        self.get_cdps = read_test_data("GET_CDP_PROCESS_LIST")
        self.get_wds = read_test_data("GET_WD_LIST")
        self.wd_payload = read_test_data("WD_PAYLOAD")
        self.rule_payload = read_test_data("FULL_MATCH_RULE_PAYLOAD")
        self.cdp_payload = read_test_data("CDP_PROCESS_PAYLOAD")

    def test_rule_exist_without_name(self):
        print("Running test_rule_exist_without_name...")
        new_payload = copy.deepcopy(self.rule_payload)
        new_payload['rules'][0].pop('name')

        with self.assertRaises(Exception) as cm:
            self.services.is_rule_exist(new_payload)

        self.assertIn(RULE_EXCEP, str(cm.exception))
        print("Test test_rule_exist_without_name is passed successfully")

    @patch("app.services.cd_service.CDServices._CDServices__get_rules")
    def test_rule_exist_with_empty_getrules(self, mock_func):
        print("Running test_rule_exist_with_empty_getrules...")
        mock_func.side_effect = partial(mock_request, param="NO_GET_RULES", returnValue=True)
        with self.assertRaises(Exception) as cm:
            self.services.is_rule_exist(self.rule_payload['rules'][0])

        self.assertIn(GET_RULE_EXCEP, str(cm.exception))
        print("Test test_rule_exist_with_empty_getrules is passed successfully")

    @patch("app.services.cd_service.CDServices._CDServices__get_rules")
    def test_rule_exist_without_rules(self, mock_func):
        print("Running test_rule_exist_without_rules...")
        mock_func.side_effect = partial(mock_request, param="NO_RULE", returnValue=True)  #

        status, entry_type = self.services.is_rule_exist(self.rule_payload['rules'][0])
        self.assertEqual(status, False)
        self.assertEqual(entry_type, 'INSERT')
        print("Test test_rule_exist_without_rules is passed successfully")

    @patch("app.services.cd_service.CDServices._CDServices__get_rules")
    def test_rule_exist_with_no_match(self, mock_func):
        print("Running test_rule_exist_with_no_match...")
        mock_func.side_effect = partial(mock_request, param="NO_MATCH", data=self.get_rules, returnValue=True)
        new_payload = copy.deepcopy(self.rule_payload)
        new_payload['rules'][0]['name']=INTERFACE_NAME

        status, entry_type = self.services.is_rule_exist(new_payload['rules'][0])
        self.assertEqual(status, False)
        self.assertEqual(entry_type, 'INSERT')
        print("Test test_rule_exist_with_no_match is passed successfully")

    @patch("app.services.cd_service.CDServices._CDServices__get_rules")
    def test_rule_exist_with_partial_match(self, mock_func):
        print("Running test_rule_exist_with_partial_match...")
        mock_func.side_effect = partial(mock_request, param="PARTIAL_MATCH", data=self.get_rules, returnValue=True)
        new_payload = copy.deepcopy(self.rule_payload)
        new_payload['rules'][0]['ruleStatus'] = "Disabled"

        status, entry_type = self.services.is_rule_exist(new_payload['rules'][0])
        self.assertEqual(status, False)
        self.assertEqual(entry_type, 'UPDATE')
        print("Test test_rule_exist_with_partial_match is passed successfully")

    @patch("app.services.cd_service.CDServices._CDServices__get_rules")
    def test_rule_exist_with_full_match(self, mock_func):
        print("Running test_rule_exist_with_full_match...")
        mock_func.side_effect = partial(mock_request, param="FULL_MATCH", data=self.get_rules, returnValue=True)
        status, entry_type = self.services.is_rule_exist(self.rule_payload['rules'][0])
        self.assertEqual(status, True)
        self.assertEqual(entry_type, 'SKIP')
        print("Test test_rule_exist_with_full_match is passed successfully")

    def test_logout(self):
        print("Running test_logout...")
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_request, param="SIGNOUT")
            status, entry_type = self.services._CDServices__sign_out()
            self.assertEqual(status, True)
            self.assertEqual(entry_type, 'SIGNOUT')

        print("Test test_logout is passed successfully")

    # def test_cdp_deploy(self):
    #     print("Running test_cdp_deploy...")
    #     with self.assertRaises(Exception) as cm:
    #         self.services.deploy_cdp("test.cdp", self.cdp_payload, "unix")
    #
    #     self.assertIn(GET_RULE_EXCEP, str(cm.exception))
    #
    #     print("Test test_cdp_deploy is passed successfully")
    #
    # def test_deploy_watch_dir(self):
    #     print("Running test_deploy_watch_dir...")
    #     with patch("requests.Session.request") as mq:
    #         mq.side_effect = partial(mock_request, param="NO_RULE")
    #         status, entry_type = self.services.deploy_watch_dir(self.rule_payload['rules'][0])
    #         self.assertEqual(status, False)
    #         self.assertEqual(entry_type, 'INSERT')
    #
    #     print("Test test_deploy_watch_dir is passed successfully")

    def test_deploy_rule(self):
        print("Running test_cdp_deploy...")
        with patch("requests.Session.request") as mq:
            # Coverage if wrong json
            mq.side_effect = partial(mock_request, param="FULL_MATCH", data=self.get_rules)
            #Coverage on exception if json wrong
            with self.assertRaises(Exception) as cm:
                self.services.deploy_rule(self.rule_payload['rules'][0])
            self.assertIn(RULE_JSON_EXCEP, str(cm.exception))

        with patch("requests.Session.request") as mq:
            #Coverage if mode preview
            mq.side_effect = partial(mock_request, param="FULL_MATCH")
            with self.assertLogs(level='DEBUG') as cml:
                self.services.deploy_rule(json.dumps(self.rule_payload['rules'][0]))
            self.assertTrue(
                any(RULE_PREVIEW_LOG in line for line in cml.output),
                "Rule_Payload log line not found in logs",
            )

        with patch("requests.Session.request") as mq:
            # Coverage if update the rule
            mq.side_effect = partial(mock_request, param="PARTIAL_MATCH", data=self.get_rules)
            with self.assertLogs(level='INFO') as cml:
                new_payload = copy.deepcopy(self.rule_payload)
                new_payload['rules'][0]['ruleStatus'] = "Disabled"
                self.services.deploy_rule(json.dumps(new_payload['rules'][0]), mode='execute')
            self.assertTrue(
                any(RULE_UPDATE_LOG in line for line in cml.output),
                "Rule update log line not found in logs",
            )

        with patch("requests.Session.request") as mq:
            # Coverage if insert the rule
            mq.side_effect = partial(mock_request, param="NO_MATCH", data=self.get_rules)
            with self.assertLogs(level='INFO') as cml:
                new_payload = copy.deepcopy(self.rule_payload)
                new_payload['rules'][0]['name'] = INTERFACE_NAME
                self.services.deploy_rule(json.dumps(new_payload['rules'][0]), mode='execute')
            self.assertTrue(
                any(RULE_INSERT_LOG in line for line in cml.output),
                "Rule insert log line not found in logs",
            )

        print("Test test_cdp_deploy is passed successfully")

if __name__ == "__main__":
    unittest.main()
