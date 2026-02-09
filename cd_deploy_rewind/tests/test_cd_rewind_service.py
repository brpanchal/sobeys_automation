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
        self.fake_args.env = ENV
        self.fake_args.execution_mode = EXECUTION_MODE
        self.fake_args.base_url = BASE_URL
        self.fake_args.host_dict = {}
        self.test_data= self.read_file("node_list")
        self.process_test_data = self.read_file("process_list")
        self.wd_rule_test_data = self.read_file("wd_n_rule_data")
        self.process_data = self.read_file("process_data")
        self.invalid_process_list = self.read_file("invalid_process_list")

    @staticmethod
    def read_file(file_name):
        with open(os.path.join(os.path.dirname(__file__)+TEST_DATA_PATH, f"{file_name}.json"), "r") as read_file:
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
            self.assertTrue(any(CD_SIGN_ON in line for line in cml.output), CD_SIGN_ON_MSG,)

    def test_ensure_signed_on_windows_os(self):
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_request)

            with self.assertLogs(level='DEBUG') as cm:
                ensure_signed_on(self.fake_args.env, self.test_data[1])
                ensure_sign_out(self.fake_args.env)
            self.assertTrue(any(CD_SIGN_ON in line for line in cm.output), CD_SIGN_ON_MSG,)

    def test_get_payload(self):
        testdata = copy.deepcopy(self.test_data)
        payload, host_dict = get_payload(testdata[1])
        self.assertEqual(payload, {})
        self.assertEqual(host_dict, EXPECTED_PAYLOAD)

        testdata_1 = copy.deepcopy(self.test_data)
        testdata_1[1].update({'test':"dummy"})
        payload, host_dict = get_payload(testdata_1[1])
        self.assertEqual(payload, {'test':"dummy"})
        self.assertEqual(host_dict, EXPECTED_PAYLOAD)

        with self.assertRaises(Exception) as cm:
            get_payload([])
        self.assertIn(PAYLOAD_EXCEPTION, str(cm.exception))

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
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_request, process_list=process_data, wd_rule_data=wd_rule_data)
            with self.assertLogs(level='INFO') as cm:
                result_1, result_2 = get_cd_artifacts(self.fake_args.env)
                display_cd_artifacts(result_1, result_2, self.fake_args)

            self.assertTrue(
                any(WD_EXPECTED in line for line in cm.output), WD_LOG_MSG,
            )

            self.assertTrue(
                any(RULE_EXPECTED in line for line in cm.output), RULE_LOG_MSG,
            )

            self.assertTrue(
                any(PROCESS_EXPECTED in line for line in cm.output), PROCESS_LOG_MSG,
            )

            self.assertEqual(len(cm.output), 3)

    def test_display_cd_artifacts_invalid_data(self):
        process_data = copy.deepcopy(self.invalid_process_list)
        wd_rule_data = copy.deepcopy(self.wd_rule_test_data)
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_request, process_list=process_data, wd_rule_data=wd_rule_data)
            with self.assertLogs(level='INFO') as cm:
                result_1, result_2 = get_cd_artifacts(self.fake_args.env)
                display_cd_artifacts(result_1, result_2, self.fake_args)

            self.assertFalse(
                any(PROCESS_EXPECTED in line for line in cm.output), PROCESS_LOG_MSG,
            )
            self.assertEqual(len(cm.output), 2)

    def test_get_cd_artifacts_backup(self):
        process_list = copy.deepcopy(self.process_test_data)
        wd_rule_data = copy.deepcopy(self.wd_rule_test_data)
        process_data = copy.deepcopy(self.process_data)
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_request, process_list=process_list, wd_rule_data=wd_rule_data, process_data=process_data)
            with self.assertLogs(level='INFO') as cm:
                get_cd_artifacts(self.fake_args.env, backup=True, node="Sample")

            self.assertTrue(
                any(START_BACKUP_EXPECTED in line for line in cm.output),
                START_BACKUP_LOG_MSG,
            )

            self.assertTrue(
                any(COMPLETE_BACKUP_EXPECTED in line for line in cm.output),
                COMPLETE_BACKUP_LOG_MSG,
            )

    def test_count_dicts(self):
        data = copy.deepcopy(self.test_data)
        count = count_dicts(data)
        self.assertEqual(count, 3)

        count = count_dicts(data[0])
        self.assertEqual(count, 1)

        count = count_dicts('sample')
        self.assertEqual(count, 0)

    def test_run_cd_rewind_service(self):
        process_list = copy.deepcopy(self.process_test_data)
        wd_rule_data = copy.deepcopy(self.wd_rule_test_data)
        process_data = copy.deepcopy(self.process_data)
        test_data = copy.deepcopy(self.test_data)
        data_ready = [[test_data[1]], [test_data[0]], [test_data[2]]]
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_request, process_list=process_list, wd_rule_data=wd_rule_data, process_data=process_data)
            with self.assertLogs(level='INFO') as cm:
                run_cd_rewind_service(data_ready, self.fake_args)

            self.assertTrue(
                any(PREVIEW_EXPECTED in line for line in cm.output),
                PREVIEW_LOG_MSG,
            )

            self.assertTrue(
                any(BACKUP_SUMMARY_EXPECTED in line for line in cm.output),
                BACKUP_SUMMARY_LOG_MSG,
            )

            self.assertTrue(
                any(STATUS_EXPECTED in line for line in cm.output),
                STATUS_LOG_MSG,
            )

            self.assertTrue(
                any( TABLE_EXPECTED in line for line in cm.output),
                TABLE_LOG_MSG,
            )

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_request, process_list=process_list, wd_rule_data=wd_rule_data, process_data=process_data)
            with self.assertLogs(level='DEBUG') as cm:
                self.arg = MagicMock()
                self.arg.env = 'dev'
                self.arg.execution_mode = 'execute'
                test_data = copy.deepcopy(self.test_data)
                data_ready = [[test_data[1]], [test_data[0]], [test_data[2]]]
                run_cd_rewind_service(data_ready, self.arg)

            self.assertTrue(
                any(EXECUTION_MODE_EXPECTED in line for line in cm.output),
                EXECUTION_MODE_LOG_MSG,
            )

            with self.assertLogs(level='INFO') as cm:
                self.arg = MagicMock()
                self.arg.env = 'dev'
                self.arg.execution_mode = 'execute'
                test_data = copy.deepcopy(self.test_data)
                data_ready = [[test_data[1]], [test_data[0]], [test_data[2]]]
                run_cd_rewind_service(data_ready, self.arg)

            self.assertTrue(
                any(COMPLETE_BACKUP_MSG in line for line in cm.output),
                COMPLETE_BACKUP_LOG,
            )

    def test_run_cd_rewind_service_failed(self):
        process_list = copy.deepcopy(self.process_test_data)
        wd_rule_data = copy.deepcopy(self.wd_rule_test_data)
        process_data = copy.deepcopy(self.process_data)
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_failed_request, process_list=process_list, wd_rule_data=wd_rule_data, process_data=process_data)
            with self.assertLogs(level='ERROR') as cm:
                test_data = copy.deepcopy(self.test_data)
                data_ready = [[test_data[1]], [test_data[0]], [test_data[2]]]
                run_cd_rewind_service(data_ready, self.fake_args)

            self.assertTrue(
                any(PROCESS_FAILED_EXPECTED in line for line in cm.output),
                PROCESS_FAILED_LOG_MSG,
            )
            self.assertEqual(len(cm.output), 3)

    def test_run_cd_rewind_service_exception(self):
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_request)
            with self.assertRaises(Exception) as cm:
                run_cd_rewind_service(None, self.fake_args)
            self.assertIn(CD_REWIND_EXCEPTION, str(cm.exception))

    def test_send_request_exception(self):
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='HTTPError')
            with self.assertRaises(Exception) as ctx:
                send_request('GET', self.fake_args.base_url, self.fake_args.env)

            self.assertIn(HTTPERROR_EXPECTED, str(ctx.exception))
            self.assertIn(ERROR_400, str(ctx.exception))

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='RequestExceptionWithResp')
            with self.assertRaises(Exception) as ctx:
                send_request('GET', self.fake_args.base_url, self.fake_args.env)

            self.assertIn(REQUEST_EXCEPTION, str(ctx.exception))
            self.assertIn(ERROR_FOUND, str(ctx.exception))

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='RequestException')
            with self.assertRaises(Exception) as ctx:
                send_request('GET', self.fake_args.base_url, self.fake_args.env)

            self.assertIn(REQUEST_EXCEPTION, str(ctx.exception))
            self.assertIn(ERROR_404, str(ctx.exception))

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request)
            with self.assertRaises(Exception) as ctx:
                send_request('GET', self.fake_args.base_url, self.fake_args.env)

            self.assertIn(UNEXPECTED_ERROR, str(ctx.exception))
            self.assertIn(ERROR_500, str(ctx.exception))

    def test_sign_on_exception(self):
        testdata = copy.deepcopy(self.test_data)
        _, host_dict = get_payload(testdata[1])
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='HTTPError')
            with self.assertRaises(Exception) as ctx:
                sign_on(self.fake_args.base_url, self.fake_args.env, host_dict)

            self.assertIn(HTTP_ERROR_TEXT, str(ctx.exception))
            self.assertIn(ERROR_FOUND, str(ctx.exception))

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='RequestExceptionWithResp')
            with self.assertRaises(Exception) as ctx:
                sign_on(self.fake_args.base_url, self.fake_args.env, host_dict)

            self.assertIn(REQUEST_EXCEPTION, str(ctx.exception))
            self.assertIn(ERROR_FOUND, str(ctx.exception))

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='RequestException')
            with self.assertRaises(Exception) as ctx:
                sign_on(self.fake_args.base_url, self.fake_args.env, host_dict)

            self.assertIn(REQUEST_EXCEPTION, str(ctx.exception))
            self.assertIn(ERROR_404, str(ctx.exception))

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request)
            with self.assertRaises(Exception) as ctx:
                sign_on(self.fake_args.base_url, self.fake_args.env, host_dict)

            self.assertIn(UNEXPECTED_ERROR_CODE, str(ctx.exception))
            self.assertIn(ERROR_500, str(ctx.exception))

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='HTTPErrorWithoutResp')
            with self.assertRaises(Exception) as ctx:
                sign_on(self.fake_args.base_url, self.fake_args.env, host_dict)

            self.assertIn(HTTP_ERROR_CODE, str(ctx.exception))
            self.assertIn(ERROR_404, str(ctx.exception))

    def test_render_table(self):
        table = render_table(
            headers=['Data'],
            rows=[],
            title='Empty Data Details',
            style="unicode",
            padding=7,
            max_widths=200
        )
        self.assertIn(NO_ARTIFACTS, str(table))



