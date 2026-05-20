import unittest
from app.services.cd_service import CDServices
from app.models.connect_direct import ConnectDirect
from dotenv import load_dotenv
from unittest.mock import patch, MagicMock
from functools import partial
import copy
import json
from tests.constants import *
from tests.helper import *
import logging
import os

logger = logging.getLogger(__name__)

class TestCDService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load .env only once for the whole test class (faster, less noise)
        load_dotenv()
        cls.cd_obj = ConnectDirect()

    def setUp(self):
        # Fresh service and baseline config per tests
        self.services = CDServices()
        self.get_rules = read_test_data("GET_RULES_LIST")
        self.get_cdps = read_test_data("GET_CDP_PROCESS_LIST")
        self.get_wds = read_test_data("GET_WD_LIST")
        self.wd_payload = read_test_data("WD_PAYLOAD")
        self.rule_payload = read_test_data("FULL_MATCH_RULE_PAYLOAD")
        self.cdp_payload = read_test_data("CDP_PROCESS_PAYLOAD")
        self.fake_args = MagicMock()
        self.fake_args.base_url = BASE_URL
        self.fake_args.env = ENV
        self.fake_args.node_data =NODE_DATA

    def test_rule_exist_without_name(self):
        """ Verifying is rule exist without rule name as no key """
        logger.info("Running test_rule_exist_without_name...")
        new_payload = copy.deepcopy(self.rule_payload)
        new_payload['rules'][0].pop('name')

        with self.assertRaises(Exception) as cm:
            self.services.is_rule_exist(new_payload)

        self.assertIn(RULE_EXCEP, str(cm.exception))
        logger.info("Test test_rule_exist_without_name is passed successfully")

    @patch("app.services.cd_service.CDServices._CDServices__get_rules")
    def test_rule_exist_with_empty_getrules(self, mock_func):
        """ Verifying is rule exist without get rules from server """
        logger.info("Running test_rule_exist_with_empty_getrules...")
        mock_func.side_effect = partial(mock_request, param="NO_GET_RULES", returnValue=True)
        with self.assertRaises(Exception) as cm:
            self.services.is_rule_exist(self.rule_payload['rules'][0])

        self.assertIn(GET_RULE_EXCEP, str(cm.exception))
        logger.info("Test test_rule_exist_with_empty_getrules is passed successfully")

    @patch("app.services.cd_service.CDServices._CDServices__get_rules")
    def test_rule_exist_without_rules(self, mock_func):
        """ Verifying is rule exist without rules as no key """
        logger.info("Running test_rule_exist_without_rules...")
        mock_func.side_effect = partial(mock_request, param="NO_RULE", returnValue=True)  #

        status, entry_type = self.services.is_rule_exist(self.rule_payload['rules'][0])
        self.assertEqual(status, False)
        self.assertEqual(entry_type, 'INSERT')
        logger.info("Test test_rule_exist_without_rules is passed successfully")

    @patch("app.services.cd_service.CDServices._CDServices__get_rules")
    def test_rule_exist_with_no_match(self, mock_func):
        """ Verifying is rule exist with no match found """
        logger.info("Running test_rule_exist_with_no_match...")
        mock_func.side_effect = partial(mock_request, param="NO_MATCH", data=self.get_rules, returnValue=True)
        new_payload = copy.deepcopy(self.rule_payload)
        new_payload['rules'][0]['name']=INTERFACE_NAME

        status, entry_type = self.services.is_rule_exist(new_payload['rules'][0])
        self.assertEqual(status, False)
        self.assertEqual(entry_type, 'INSERT')
        logger.info("Test test_rule_exist_with_no_match is passed successfully")

    @patch("app.services.cd_service.CDServices._CDServices__get_rules")
    def test_rule_exist_with_partial_match(self, mock_func):
        """ Verifying is rule exist with partial match found """
        logger.info("Running test_rule_exist_with_partial_match...")
        mock_func.side_effect = partial(mock_request, param="PARTIAL_MATCH", data=self.get_rules, returnValue=True)
        new_payload = copy.deepcopy(self.rule_payload)
        new_payload['rules'][0]['ruleStatus'] = "Disabled"

        status, entry_type = self.services.is_rule_exist(new_payload['rules'][0])
        self.assertEqual(status, False)
        self.assertEqual(entry_type, 'UPDATE')
        logger.info("Test test_rule_exist_with_partial_match is passed successfully")

    @patch("app.services.cd_service.CDServices._CDServices__get_rules")
    def test_rule_exist_with_full_match(self, mock_func):
        """ Verifying is rule exist with full match found """
        logger.info("Running test_rule_exist_with_full_match...")
        mock_func.side_effect = partial(mock_request, param="FULL_MATCH", data=self.get_rules, returnValue=True)
        status, entry_type = self.services.is_rule_exist(self.rule_payload['rules'][0])
        self.assertEqual(status, True)
        self.assertEqual(entry_type, 'SKIP')
        logger.info("Test test_rule_exist_with_full_match is passed successfully")

    def test_logout(self):
        logger.info("Running test_logout...")
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_request, param="SIGNOUT")
            status, entry_type = self.services._CDServices__sign_out()
            self.assertEqual(status, True)
            self.assertEqual(entry_type, 'SIGNOUT')

        logger.info("Test test_logout is passed successfully")

    def test_deploy_rule_with_invalid_json(self):
        """ Verifying deploy rule with invalid json """
        logger.info("Running test_cdp_deploy...")
        with patch("requests.Session.request") as mq:
            # Coverage if wrong json
            mq.side_effect = partial(mock_request, param="FULL_MATCH", data=self.get_rules)
            #Coverage on exception if json wrong
            with self.assertRaises(Exception) as cm:
                self.services.deploy_rule(self.rule_payload['rules'][0])
            self.assertIn(RULE_JSON_EXCEP, str(cm.exception))

    def test_deploy_rule_with_fullmatch_preview_mode(self):
        with patch("requests.Session.request") as mq:
            #Coverage if mode preview
            mq.side_effect = partial(mock_request, param="FULL_MATCH")
            with self.assertLogs(level='DEBUG') as cml:
                self.services.deploy_rule(json.dumps(self.rule_payload['rules'][0]))
            self.assertTrue(
                any(RULE_PREVIEW_LOG in line for line in cml.output),
                "Rule_Payload log line not found in logs",
            )

    def test_deploy_rule_with_update_rules(self):
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

    def test_deploy_rule_with_no_match(self):
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

        logger.info("Test test_cdp_deploy is passed successfully")

    @patch("app.services.cd_service.CDServices._CDServices__ensure_signed_on")
    def test_send_request_alreadyexist_exception(self, mock_request):
        mock_request.side_effect = partial(mock_func_request)
        # Verifying all exception in send request call
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='HTTPError', flag="AleadyExist")
            status, res = self.services._CDServices__send_request('GET', self.fake_args.base_url, self.fake_args.env)

            self.assertIn("Add rule failed, Rule:ABC already exists.", res)
            self.assertEqual(status, False)

    @patch("app.services.cd_service.CDServices._CDServices__ensure_signed_on")
    def test_send_request_exception(self, mock_request):
        mock_request.side_effect = partial(mock_func_request)
        # Verifying all exception in send request call
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='HTTPError')
            with self.assertRaises(Exception) as ctx:
                self.services._CDServices__send_request('GET', self.fake_args.base_url, self.fake_args.env)

            self.assertIn(HTTP_ERROR, str(ctx.exception))
            self.assertIn(ERROR_FOUND, str(ctx.exception))

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='RequestExceptionWithResp')
            with self.assertRaises(Exception) as ctx:
                self.services._CDServices__send_request('GET', self.fake_args.base_url, self.fake_args.env)

            self.assertIn(REQUEST_EXCEPTION, str(ctx.exception))
            self.assertIn(ERROR_FOUND, str(ctx.exception))

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='RequestException')
            with self.assertRaises(Exception) as ctx:
                self.services._CDServices__send_request('GET', self.fake_args.base_url, self.fake_args.env)

            self.assertIn(REQUEST_EXCEPTION, str(ctx.exception))
            self.assertIn(ERROR_404, str(ctx.exception))

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request)
            with self.assertRaises(Exception) as ctx:
                self.services._CDServices__send_request('GET', self.fake_args.base_url, self.fake_args.env)

            self.assertIn(UNEXPECTED_ERROR, str(ctx.exception))
            self.assertIn(ERROR_500, str(ctx.exception))

    def test_sign_on_exception(self):
        # Verifying sign on method with all exceptions

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='HTTPError')
            with self.assertRaises(Exception) as ctx:
                self.services._CDServices__sign_on(self.fake_args.base_url)

            self.assertIn(HTTP_ERROR_TEXT, str(ctx.exception))
            self.assertIn(ERROR_FOUND, str(ctx.exception))

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='RequestExceptionWithResp')
            with self.assertRaises(Exception) as ctx:
                self.services._CDServices__sign_on(self.fake_args.base_url)

            self.assertIn(REQUEST_EXCEPTION, str(ctx.exception))
            self.assertIn(ERROR_FOUND, str(ctx.exception))

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='RequestException')
            with self.assertRaises(Exception) as ctx:
                self.services._CDServices__sign_on(self.fake_args.base_url)

            self.assertIn(REQUEST_EXCEPTION, str(ctx.exception))
            self.assertIn(ERROR_404, str(ctx.exception))

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request)
            with self.assertRaises(Exception) as ctx:
                self.services._CDServices__sign_on(self.fake_args.base_url)

            self.assertIn(UNEXPECTED_ERROR_CODE, str(ctx.exception))
            self.assertIn(ERROR_500, str(ctx.exception))

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='HTTPErrorWithoutResp')
            with self.assertRaises(Exception) as ctx:
                self.services._CDServices__sign_on(self.fake_args.base_url)

            self.assertIn(HTTP_ERROR_CODE, str(ctx.exception))
            self.assertIn(ERROR_404, str(ctx.exception))

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_failed_request)
            with self.assertLogs(level='DEBUG') as ctx:
                self.services._CDServices__sign_on(self.fake_args.base_url)

            self.assertIn(CD_SIGN_ON_FAILED, str(ctx.output))

    @patch.dict(os.environ, PSWD_EXCEPTION_DATA, clear=True)
    def test_initialize_cd_properties_with_exception(self):
        expected_msgs = NODE_KEYS
        with self.assertLogs(level="DEBUG") as ctx:
            self.services.initialize_cd_properties(self.fake_args.env, NODE_DATA['os_type'], NODE_DATA['hostname'], "exception", NODE_DATA['node'])

        self.assertTrue(
            any(
                any(msg in line for msg in expected_msgs)
                for line in ctx.output
            ),
            "log line not found in logs",
        )

    def test_initialize_cd_properties_validation(self):
        with self.assertRaises(Exception) as ctx:
            self.services.initialize_cd_properties(self.fake_args.env, "", None, "", "")
        self.assertIn("Hostname cannot be None.", str(ctx.exception))

        with self.assertRaises(Exception) as ctx:
            self.services.initialize_cd_properties(self.fake_args.env, None, "", "", "")
        self.assertIn("OS cannot be None.", str(ctx.exception))

        with self.assertRaises(Exception) as ctx:
            self.services.initialize_cd_properties(self.fake_args.env, "", "", None, "")
        self.assertIn("Credential cannot be None.", str(ctx.exception))

        with self.assertRaises(Exception) as ctx:
            self.services.initialize_cd_properties(self.fake_args.env, "", "", "None", "")
        self.assertIn("Password type is invalid (given as 'None'). it should be as per defined types", str(ctx.exception))

        with self.assertRaises(Exception) as ctx:
            self.services.initialize_cd_properties(self.fake_args.env, "", "", "default", None)
        self.assertIn("Node name cannot be None.", str(ctx.exception))

    def test_initialize_cd_properties_win_node(self):
        expected_msgs = NODE_KEYS
        with self.assertLogs(level="DEBUG") as ctx:
            self.services.initialize_cd_properties(self.fake_args.env, "windows system", NODE_DATA['hostname'], NODE_DATA['password'], NODE_DATA['node'])
        self.assertTrue(
            any(
                any(msg in line for msg in expected_msgs)
                for line in ctx.output
            ),
            "log line not found in logs",
        )

    def test_initialize_cd_properties_unix_node(self):
        expected_msgs = NODE_KEYS
        with self.assertLogs(level="DEBUG") as ctx:
            self.services.initialize_cd_properties(self.fake_args.env, "unix system", NODE_DATA['hostname'], NODE_DATA['password'], NODE_DATA['node'])
        self.assertTrue(
            any(
                any(msg in line for msg in expected_msgs)
                for line in ctx.output
            ),
            "log line not found in logs",
        )

        with self.assertRaises(Exception) as ctx:
            self.services.initialize_cd_properties(self.fake_args.env, "unix system", "abc.com", "exception", "ABC")

        self.assertIn("Connect:Direct Username and password not provided in environment file(.env) as per password exception case for node", str(ctx.exception))

    def test_is_cdp_exist(self):
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_func_request, node=self.get_cdps)
            status = self.services.is_cdp_exist(MATCHED_CDP)

        self.assertEqual(status, True)

    def test_is_cdp_exist_empty_node_data(self):

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_func_request, node=[{}])
            status = self.services.is_cdp_exist(MATCHED_CDP)

        self.assertEqual(status, False)

    def test_is_cdp_exist_empty_payload(self):
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_func_request, node=[{ "PROCESSFILES": []}])
            status = self.services.is_cdp_exist(MATCHED_CDP)

        self.assertEqual(status, False)

    def test_is_cdp_exist_no_processfiles(self):
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_func_request, node=[{"totalRecords": 0}])
            status = self.services.is_cdp_exist(MATCHED_CDP)

        self.assertEqual(status, False)

    def test_is_cdp_exist_wrong_cdp(self):
        with patch("requests.Session.request") as mq:
            with self.assertRaises(Exception) as ctx:
                mq.side_effect = partial(mock_func_request)
                status = self.services.is_cdp_exist(MATCHED_CDP)

        self.assertIn("0", str(ctx.exception))

        with patch("requests.Session.request") as mq:
            with self.assertRaises(Exception) as ctx:
                mq.side_effect = partial(mock_excep_request, param='HTTPError', flag="AleadyExist")
                status = self.services.is_cdp_exist(MATCHED_CDP)

            self.assertIn("Skipping to create CD Process due to get CD get_process_library Failed!", str(ctx.exception))

    def test_is_watch_dir_exist(self):
        watchdirname = MATCHED_WD
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_func_request, node=self.get_wds)
            status = self.services.is_watch_dir_exist(watchdirname)

        self.assertEqual(status, True)

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_func_request, node={})
            status = self.services.is_watch_dir_exist(watchdirname)

        self.assertEqual(status, False)

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_func_request, node={"totalRecords": 0})
            status = self.services.is_watch_dir_exist(watchdirname)

        self.assertEqual(status, False)

        with patch("requests.Session.request") as mq:
            with self.assertRaises(Exception) as ctx:
                mq.side_effect = partial(mock_func_request, node={ "watchDirList": []})
                status = self.services.is_watch_dir_exist(watchdirname)

        self.assertIn("totalRecords", str(ctx.exception))


        with patch("requests.Session.request") as mq:
            with self.assertRaises(Exception) as ctx:
                mq.side_effect = partial(mock_excep_request, param='HTTPError', flag="AleadyExist")
                status = self.services.is_watch_dir_exist(watchdirname)

            self.assertIn("Skipping to create watch directory due to CD get_watch_directories Failed!", str(ctx.exception))

    def test_deploy_watch_dir(self):
        with self.assertRaises(Exception) as ctx:
            self.services.deploy_watch_dir(None)

        self.assertIn( "Failed to deploy watch_dir, RuntimeError", str(ctx.exception))

        with patch("requests.Session.request") as mq:
            with self.assertLogs(level="DEBUG") as log:
                mq.side_effect = partial(mock_func_request, node=self.get_wds)
                self.services.deploy_watch_dir(json.dumps(self.wd_payload))

            self.assertIn("already exists.", str(log.output))

        with patch("requests.Session.request") as mq:
            with self.assertLogs(level="DEBUG") as log:
                mq.side_effect = partial(mock_func_request, node=self.get_wds)
                self.wd_payload['watchedDir'] = TEST_WD
                self.services.deploy_watch_dir(json.dumps(self.wd_payload))

            self.assertIn("Watch_Dir_Payload to be deployed", str(log.output))

        with patch("requests.Session.request") as mq:
            with self.assertLogs(level="DEBUG") as log:
                mq.side_effect = partial(mock_func_request, node=self.get_wds)
                self.wd_payload['watchedDir'] = TEST_WD
                self.services.deploy_watch_dir(json.dumps(self.wd_payload), 'execute')
            self.assertIn('Executing CD create_watch_directory', str(log.output))
            self.assertIn("Executing CD apply_changes", str(log.output))

    def test_deploy_cdp(self):
        with self.assertRaises(Exception) as ctx:
            self.services.deploy_cdp(self.cdp_payload['processFileName'], None, 'unix')
        self.assertIn("Failed to deploy CDP", str(ctx.exception))

        with patch("requests.Session.request") as mq:
            with self.assertLogs(level="DEBUG") as ctx:
                mq.side_effect = partial(mock_func_request, node=self.get_cdps)
                self.services.deploy_cdp(self.cdp_payload['processFileName'], json.dumps(self.cdp_payload), 'unix')
            self.assertIn("already exists", str(ctx.output))

        with patch("requests.Session.request") as mq:
            with self.assertRaises(Exception) as ctx:
                mq.side_effect = partial(mock_func_request, node=self.get_cdps)
                self.services.deploy_cdp(self.cdp_payload["processFileName"], json.dumps(self.cdp_payload), 'windows')
            self.assertIn(f"CDP Process name '{self.cdp_payload["processFileName"].split(".")[0]}' is too long. Can be 8 characters maximum for windows system.", str(ctx.exception))

        with patch("requests.Session.request") as mq:
            with self.assertLogs(level="DEBUG") as ctx:
                mq.side_effect = partial(mock_func_request, node=self.get_cdps)
                self.cdp_payload["processFileName"] = TEST_CDP_NAME
                self.services.deploy_cdp(self.cdp_payload["processFileName"], json.dumps(self.cdp_payload), 'unix')
            self.assertIn("CDP_Payload:", str(ctx.output))

        with patch("requests.Session.request") as mq:
            with self.assertLogs(level="DEBUG") as ctx:
                mq.side_effect = partial(mock_func_request, node=self.get_cdps)
                self.cdp_payload["processFileName"] = TEST_CDP_NAME
                self.services.deploy_cdp(self.cdp_payload["processFileName"], json.dumps(self.cdp_payload), 'unix', 'execute')
            self.assertIn("Executing CD create_cdp_file", str(ctx.output))

    def test_remove_rule(self):
        self.assertRaises(RuntimeError, self.services.remove_rule, None)
        name = self.rule_payload['rules'][0]['name']
        with self.assertLogs(level="INFO") as ctx:
            self.services.remove_rule(json.dumps(self.rule_payload['rules'][0]))
        self.assertIn(f"Rule ({name}) to be removed. Payload:", str(ctx.output))

        with patch("requests.Session.request") as mq:
            with self.assertLogs(level="INFO") as ctx:
                mq.side_effect = partial(mock_func_request, node=self.get_rules)
                self.services.remove_rule(json.dumps(self.rule_payload['rules'][0]), "execute")
            self.assertIn("Rule removing process start..", str(ctx.output))
            self.assertIn(f"Rule ({name}) removed successfully with payload:", str(ctx.output))

        with patch("requests.Session.request") as tq:
            with patch("app.services.cd_service.CDServices._CDServices__remove_rule") as mq:
                with self.assertLogs(level="INFO") as ctx:
                    mq.return_value = False, {}
                    tq.side_effect = partial(mock_func_request)
                    self.services.remove_rule(json.dumps(self.rule_payload['rules'][0]), "execute")
                self.assertIn("Rule removing process start..", str(ctx.output))
                self.assertIn("Rule not removed due to {}", str(ctx.output))

    def test_deploy_cd_artifacts(self):
        self.assertRaises(AttributeError, self.services.deploy_cd_artifacts, None,self.fake_args.env, None)
        self.assertRaises(RuntimeError, self.services.deploy_cd_artifacts, self.cd_obj, self.fake_args.env, None)

        self.cd_obj.os_type = NODE_DATA['os_type']
        self.cd_obj.node_name = NODE_DATA['node']
        self.cd_obj.hostname = NODE_DATA['hostname']
        self.cd_obj.credentials = NODE_DATA['password']
        self.cd_obj.cdp = json.dumps(self.cdp_payload)
        self.cd_obj.watch_dir = json.dumps(self.wd_payload)
        self.cd_obj.rule = json.dumps(self.rule_payload)
        self.cd_obj.cdp_name = TEST_CDP_NAME
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_failed_request)
            with self.assertRaises(Exception) as ctx:
                self.services.deploy_cd_artifacts(self.cd_obj,self.fake_args.env, NODE_DATA['node'])

            self.assertIn("Failed to sign on to Connect:Direct", str(ctx.exception))

        with patch("requests.Session.request") as mq:
            with patch("app.services.cd_service.CDServices.deploy_cdp") as cdp:
                with patch("app.services.cd_service.CDServices.deploy_watch_dir") as wd:
                    with patch("app.services.cd_service.CDServices.deploy_rule") as dr:
                        mq.side_effect = partial(mock_func_request)
                        cdp.side_effect = partial(mock_func_request)
                        wd.side_effect = partial(mock_func_request)
                        dr.side_effect = partial(mock_func_request)
                        with self.assertLogs(level="INFO") as ctx:
                            self.services.deploy_cd_artifacts(self.cd_obj,self.fake_args.env, NODE_DATA['node'], EXECUTION_TYPE[0],'Insert')

                        self.assertIn("CD artifacts processing completed.", str(ctx.output))

        with patch("requests.Session.request") as mq:
            with patch("app.services.cd_service.CDServices.remove_rule") as rr:
                mq.side_effect = partial(mock_func_request)
                rr.side_effect = partial(mock_func_request)
                with self.assertLogs(level="INFO") as ctx:
                    self.services.deploy_cd_artifacts(self.cd_obj,self.fake_args.env, NODE_DATA['node'], EXECUTION_TYPE[0],'Remove')

                self.assertIn("CD artifacts processing completed.", str(ctx.output))

if __name__ == "__main__":
    unittest.main()
