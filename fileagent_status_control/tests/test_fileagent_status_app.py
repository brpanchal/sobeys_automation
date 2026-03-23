import unittest
from unittest.mock import patch, MagicMock
from functools import partial
from tests.constants import *
from tests.helper import *
from app.fileagent_status_app import *
import  logging
import copy
from run_app import *

logger = logging.getLogger(__name__)

class TestFileAgentStatusApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load .env only once for the whole test class (faster, less noise)
        load_dotenv()
        cls.test_data = read_file(FILENAME, TEST_DATA_PATH, True)
        cls.init_data = read_file(INITFILENAME, TEST_DATA_PATH, True)

    def setUp(self):
        # Common fake args object
        self.fake_args = MagicMock()
        self.fake_args.env = ENV
        self.fake_args.execution_mode = FileAgentStatusEnum.PREVIEW
        self.fake_args.base_url = BASE_URL
        self.fake_args.host_dict = {}

    def test_ensure_signed_on(self):
        with self.assertRaises(Exception) as cm:
            ensure_signed_on(self.fake_args.env, {})
        self.assertIn("os_type", str(cm.exception))

    def test_ensure_signed_on_unix_os(self):
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_func_request)

            with self.assertLogs(level='DEBUG') as cml:
                ensure_signed_on(self.fake_args.env, self.test_data[0])
                ensure_sign_out(self.fake_args.env)
            self.assertTrue(any(CD_SIGN_ON in line for line in cml.output), CD_SIGN_ON_MSG,)

    def test_ensure_signed_on_windows_os(self):
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_func_request)

            with self.assertLogs(level='DEBUG') as cm:
                ensure_signed_on(self.fake_args.env, self.test_data[1])
                ensure_sign_out(self.fake_args.env)
            self.assertTrue(any(CD_SIGN_ON in line for line in cm.output), CD_SIGN_ON_MSG,)

    def test_get_payload(self):
        testdata = copy.deepcopy(self.test_data)
        payload, host_dict = get_payload(testdata[1])
        self.assertEqual(payload["fileagent.enable"], EXPECTED_PAYLOAD)
        self.assertEqual(host_dict, HOST_DICT_2)

        testdata_1 = copy.deepcopy(self.test_data)
        testdata_1[1].update({'test':"dummy"})
        payload, host_dict = get_payload(testdata_1[1])
        self.assertIn('test', payload)
        self.assertEqual(host_dict, HOST_DICT_2)

        payload, host_dict = get_payload(testdata_1[0])
        self.assertEqual(payload['fileagent.enable'], EXPECTED_PAYLOAD)
        self.assertEqual(host_dict, HOST_DICT_1)

        payload, host_dict = get_payload(testdata_1[2])
        self.assertEqual(payload['fileagent.enable'], EXPECTED_PAYLOAD)
        self.assertEqual(host_dict, HOST_DICT_3)

        with self.assertRaises(Exception) as cm:
            get_payload([])
        self.assertIn(PAYLOAD_EXCEPTION, str(cm.exception))
    #
    def test_get_initparam_details(self):
        with patch("requests.Session.request") as mq:
            node_data =  [[{ 'fileagent.enable': EXPECTED_PAYLOAD}]]
            mq.side_effect = partial(mock_func_request, node=node_data)
            result = get_initparam_details(self.fake_args.env, json_type=True)
            self.assertEqual(type(result[0][0]), dict)
            self.assertEqual(type(result), list)
            self.assertGreater(len(result), 0)
            self.assertEqual(result, node_data)

    def test_get_certificate_backup(self):
        with patch("requests.Session.request") as mq:
            node_data =  [[{ 'fileagent.enable': EXPECTED_PAYLOAD}]]
            mq.side_effect = partial(mock_func_request, node=node_data)
            with self.assertLogs(level='DEBUG') as cm:
                result = get_initparam_details(self.fake_args.env, backup=True, node="Sample")

            self.assertEqual(type(result[0][0]), dict)
            self.assertEqual(type(result), list)

            self.assertTrue(
                any(START_BACKUP_EXPECTED in line for line in cm.output),
                START_BACKUP_LOG_MSG,
            )

            self.assertTrue(
                any(COMPLETE_BACKUP_EXPECTED in line for line in cm.output),
                COMPLETE_BACKUP_LOG_MSG,
            )

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

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_failed_request)
            with self.assertLogs(level='DEBUG') as ctx:
                sign_on(self.fake_args.base_url, self.fake_args.env, host_dict)

            self.assertIn(CD_SIGN_ON_FAILED, str(ctx.output))

    @patch("app.fileagent_status_app.send_request")
    def test_update_initparms_data(self, mock_func):
        mock_func.side_effect = partial(mock_func_request, node=RESPONSE_DATA)
        res = update_initparam_details(self.init_data[0], self.fake_args.env)

        self.assertIn("Init Parms data has been updated successfully", res.text)
        self.assertEqual(res.status, True)

    def test_prepare_initparams_data_with_execute(self):
        result, action = prepare_initparams_data(self.test_data[0], self.init_data[0], "Y", self.fake_args.execution_mode)
        self.assertEqual(result, self.init_data[0])
        self.assertEqual(action, FileAgentStatusEnum.UPDATE)

        result, action = prepare_initparams_data(self.test_data[1], self.init_data[0], "Y", self.fake_args.execution_mode)
        self.assertEqual(result, self.init_data[0])
        self.assertEqual(action, FileAgentStatusEnum.UPDATE)

        result, action = prepare_initparams_data(self.test_data[1], self.init_data[0], "abc",
                                                 self.fake_args.execution_mode)
        self.assertEqual(result, self.init_data[0])
        self.assertEqual(action, FileAgentStatusEnum.SKIP)

    def test_prepare_initparams_data_with_preview(self):
        result, action = prepare_initparams_data(self.test_data[0], self.init_data[1], "Y", self.fake_args.execution_mode)
        self.assertEqual(result, self.init_data[1])
        self.assertEqual(action, FileAgentStatusEnum.SKIP)

        result, action = prepare_initparams_data(self.test_data[1], self.init_data[2], "Y", self.fake_args.execution_mode)
        self.assertEqual(result, self.init_data[2])
        self.assertEqual(action, FileAgentStatusEnum.SKIP)

        result, action = prepare_initparams_data(self.test_data[1], self.init_data[2], None,
                                                 self.fake_args.execution_mode)
        self.assertEqual(result, self.init_data[2])
        self.assertEqual(action, FileAgentStatusEnum.SKIP)

    def test_format_tree_report(self):
        global report_list
        result, action = prepare_initparams_data(self.test_data[0], self.init_data[1], "Y",
                                                 self.fake_args.execution_mode)
        self.assertEqual(result, self.init_data[1])
        self.assertEqual(action, FileAgentStatusEnum.SKIP)
        report = format_tree_report(report_list)
        self.assertEqual(len(report_list[0]), 8)
        self.assertEqual(report_list[0][0], "1")
        self.assertEqual(report_list[0][1], "Dummy1")
        self.assertEqual(report_list[0][2], "dummy1.com")
        self.assertEqual(report_list[0][3], "unix system")
        self.assertEqual(report_list[0][4], "cd.file.agent:cdfa.enable")
        self.assertEqual(report_list[0][5], "y")
        self.assertIn("Dummy1", report)
        self.assertIn("dummy1.com", report)
        self.assertIn("unix system", report)
        self.assertIn("FileAgent status details for all nodes", report)

    def test_format_tree_report_without_data(self):
        report_list = []
        report = format_tree_report(report_list)
        self.assertIn("— No data —", report)

    def test_prerequisite_to_process_node(self):
        with self.assertRaises(Exception) as cm:
            prerequisite_to_process_node({})
        self.assertIn("node_list not configured properly. either hostname or os_type not found or invalid values for node", str(cm.exception))

    def test_generate_report(self):
        with self.assertLogs(level='INFO') as cml:
            generate_report(self.fake_args.execution_mode, 2, 0, 0, 0, 1, 1, 13.81)
        self.assertTrue(any('Total execution duration: 13.81 seconds' in line for line in cml.output), 'not found',)
        self.assertTrue(any('Success: 2  Failed: 0  Skip:1   Update:1' in line for line in cml.output), 'not found', )
        self.assertTrue(any('ℹ️ CD File Agent status naming conventions: y/n for Unix ; Y/N for Windows' in line for line in cml.output), 'not found', )

        with self.assertLogs(level='INFO') as cml:
            generate_report('execute', 2, 0, 1, 1, 0, 0, 13.81)

        self.assertTrue(any('Total execution duration: 13.81 seconds' in line for line in cml.output), 'not found', )
        self.assertTrue(any('Success: 2  Failed: 0  Skipped:1   Updated:1' in line for line in cml.output), 'not found', )
        self.assertTrue(any(
            'ℹ️ CD File Agent status naming conventions: y/n for Unix ; Y/N for Windows' in line for line in cml.output),
                        'not found', )





