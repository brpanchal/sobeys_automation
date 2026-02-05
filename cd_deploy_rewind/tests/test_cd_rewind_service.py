import unittest
from unittest.mock import patch, MagicMock
from functools import partial
from tests.constants import *
from tests.helper import *
from app.cd_rewind_service import *
import  logging
import copy
import os, json

logger = logging.getLogger(__name__)

class TestCDRewind(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load .env only once for the whole test class (faster, less noise)
        load_dotenv()

    def setUp(self):
        # Common fake args object
        self.fake_args = MagicMock()
        self.fake_args.env = "qa"
        self.fake_args.execution_mode = "preview"
        self.fake_args.base_url = "http://dummy.com:8080"
        self.fake_args.host_dict = {}
        self.test_data= self.read_file("node_list")
        self.process_test_data = self.read_file("process_list")
        self.wd_rule_test_data = self.read_file("wd_n_rule_data")
        self.process_data = self.read_file("process_data")

    @staticmethod
    def read_file(file_name):
        with open(os.path.join(os.path.dirname(__file__)+"/testdata", f"{file_name}.json"), "r") as read_file:
            return json.load(read_file)

    def test_ensure_signed_on(self):
        with self.assertRaises(Exception) as cm:
            ensure_signed_on(self.fake_args.env, {})
        self.assertIn("os_type", str(cm.exception))

    def test_ensure_signed_on_unix_os(self):
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_request)

            with self.assertLogs(level='DEBUG') as cml:
                ensure_signed_on(self.fake_args.env, self.test_data[0])
                ensure_sign_out(self.fake_args.env)
            self.assertTrue(
                any('CDWS sign_on Successful!!' in line for line in cml.output),
                "Rule_Payload log line not found in logs",
            )

    def test_ensure_signed_on_windows_os(self):
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_request)

            with self.assertLogs(level='DEBUG') as cm:
                ensure_signed_on(self.fake_args.env, self.test_data[1])
                ensure_sign_out(self.fake_args.env)
            self.assertTrue(
                any('CDWS sign_on Successful!!' in line for line in cm.output),
                "Rule_Payload log line not found in logs",
            )

    def test_get_payload(self):
        testdata = copy.deepcopy(self.test_data)
        payload, host_dict = get_payload(testdata[1])
        self.assertEqual(payload, {})
        self.assertEqual(host_dict, {
                "node": "Dummy2",
                "hostname": "dummy2.com",
                "os_type": "windows system"
              })

        testdata_1 = copy.deepcopy(self.test_data)
        testdata_1[1].update({'test':"dummy"})
        payload, host_dict = get_payload(testdata_1[1])
        self.assertEqual(payload, {'test':"dummy"})
        self.assertEqual(host_dict, {
            "node": "Dummy2",
            "hostname": "dummy2.com",
            "os_type": "windows system"
        })

        with self.assertRaises(Exception) as cm:
            get_payload([])
        self.assertIn("Unexpected exception during payload", str(cm.exception))

    def test_get_cd_artifacts(self):
        process_data = copy.deepcopy(self.process_test_data)
        wd_rule_data = copy.deepcopy(self.wd_rule_test_data)
        with patch("requests.Session.request") as mq:
                mq.side_effect = partial(mock_request, process_list=process_data, wd_rule_data=wd_rule_data)
                result_1, result_2 = get_cd_artifacts(self.fake_args.env)
                self.assertEqual(type(result_1), dict)
                self.assertEqual(type(result_2), list)
                self.assertGreater(len(result_1), 0)
                self.assertGreater(len(result_2), 0)

    def test_display_cd_artifacts(self):
        process_data = copy.deepcopy(self.process_test_data)
        wd_rule_data = copy.deepcopy(self.wd_rule_test_data)
        process_list_data = copy.deepcopy(self.process_data)
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_request, process_list=process_data, wd_rule_data=wd_rule_data)
            with self.assertLogs(level='INFO') as cm:
                result_1, result_2 = get_cd_artifacts(self.fake_args.env)
                display_cd_artifacts(result_1, result_2, self.fake_args)

            self.assertTrue(
                any('watchDirList Artifacts for node' in line for line in cm.output),
                "watchDirList log line not found in logs",
            )
            self.assertTrue(
                any('ruleList Artifacts for node' in line for line in cm.output),
                "ruleList log line not found in logs",
            )
            self.assertTrue(
                any('PROCESSFILE' in line for line in cm.output),
                "PROCESSFILE log line not found in logs",
            )
            self.assertEqual(len(cm.output), 3)

    def test_get_cd_artifacts_backup(self):
        process_list = copy.deepcopy(self.process_test_data)
        wd_rule_data = copy.deepcopy(self.wd_rule_test_data)
        process_data = copy.deepcopy(self.process_data)
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_request, process_list=process_list, wd_rule_data=wd_rule_data, process_data=process_data)
            with self.assertLogs(level='INFO') as cm:
                get_cd_artifacts(self.fake_args.env, backup=True, node="Sample.cdp")

            self.assertTrue(
                any('Started backup of CD artifacts for node ABC' in line for line in cm.output),
                "Backup log line not found in logs",
            )

            self.assertTrue(
                any('Completed backup of CD artifacts for node ABC' in line for line in cm.output),
                "Backup log line not found in logs",
            )


