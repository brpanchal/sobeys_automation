import unittest
from unittest.mock import patch, MagicMock
from functools import partial
from tests.constants import *
from tests.helper import *
from app.fileagent_status_app import *
import logging
import copy
from run_app import *

logger = logging.getLogger(__name__)


class TestFileAgentStatusApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load .env only once for the whole test class (faster, less noise)
        load_dotenv()
        data = read_file(FILENAME, TEST_DATA_PATH, True)
        # Node data read from node_list.json as test data
        cls.test_data = cls.get_test_node_data(data)
        # Init parms data read from initparms.json as init test data
        cls.init_data = read_file(INITFILENAME, TEST_DATA_PATH, True)

    def setUp(self):
        # Common fake args object
        self.fake_args = MagicMock()
        self.fake_args.env = ENV
        self.fake_args.execution_mode = FileAgentStatusEnum.PREVIEW
        self.fake_args.base_url = BASE_URL
        self.fake_args.host_dict = {}
        self.testdata = copy.deepcopy(self.test_data)

    def tearDown(self):
        # clear/release or del obj from memory
        del self.testdata

    @classmethod
    def get_test_node_data(cls, data):
        test_data = []
        for node in data:
            test_data.append([node])
        return test_data

    def test_ensure_signed_on_empty_payload(self):
        with self.assertRaises(Exception) as cm:
            ensure_signed_on(self.fake_args.env, {})
        self.assertIn("os_type", str(cm.exception))

    def test_ensure_signed_on_unix_os(self):
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_func_request)

            with self.assertLogs(level='DEBUG') as cml:
                ensure_signed_on(self.fake_args.env, self.test_data[0][0])
                ensure_sign_out(self.fake_args.env)
            self.assertTrue(any(CD_SIGN_ON in line for line in cml.output), CD_SIGN_ON_MSG, )

    def test_ensure_signed_on_windows_os(self):
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_func_request)

            with self.assertLogs(level='DEBUG') as cm:
                ensure_signed_on(self.fake_args.env, self.test_data[1][0])
                ensure_sign_out(self.fake_args.env)
            self.assertTrue(any(CD_SIGN_ON in line for line in cm.output), CD_SIGN_ON_MSG, )

    def test_get_payload_win_os(self):
        # get node data and payload separated by windows data
        payload, host_dict = get_payload(self.testdata[1][0])
        self.assertEqual(payload["fileagent.enable"], EXPECTED_PAYLOAD)
        self.assertEqual(host_dict, HOST_DICT_2)

    def test_get_payload_new_params(self):
        # get node data with extra params and payload separated by win data
        self.testdata[1][0].update({'test': "dummy"})
        payload, host_dict = get_payload(self.testdata[1][0])
        self.assertIn('test', payload)
        self.assertEqual(host_dict, HOST_DICT_2)

    def test_get_payload_unix_os(self):
        # get payload node data and payload separated by unix data
        payload, host_dict = get_payload(self.testdata[0][0])
        self.assertEqual(payload['fileagent.enable'], EXPECTED_PAYLOAD)
        self.assertEqual(host_dict, HOST_DICT_1)

    def test_get_payload_aix_os(self):
        # get payload node data and payload separated by aix data
        payload, host_dict = get_payload(self.testdata[2][0])
        self.assertEqual(payload['fileagent.enable'], EXPECTED_PAYLOAD_N)
        self.assertEqual(host_dict, HOST_DICT_3)

    def test_get_payload_with_empty_param(self):
        # Raise exception when passing empty parms
        with self.assertRaises(Exception) as cm:
            get_payload([])
        self.assertIn(PAYLOAD_EXCEPTION, str(cm.exception))

    def test_get_initparam_details(self):
        # Mock the request call and get the initparms data from it
        with patch("requests.Session.request") as mq:
            node_data = [[{'fileagent.enable': EXPECTED_PAYLOAD}]]
            mq.side_effect = partial(mock_func_request, node=node_data)
            result = get_initparam_details(self.fake_args.env, json_type=True)
            self.assertEqual(type(result[0][0]), dict)
            self.assertEqual(type(result), list)
            self.assertGreater(len(result), 0)
            self.assertEqual(result, node_data)

    def test_get_certificate_backup(self):
        ##Mock the request call and get the initparms data from it with backup
        with patch("requests.Session.request") as mq:
            node_data = [[{'fileagent.enable': EXPECTED_PAYLOAD}]]
            mq.side_effect = partial(mock_func_request, node=node_data)
            with self.assertLogs(level='DEBUG') as cm:
                result = get_initparam_details(self.fake_args.env, backup=True, node="Sample")

            self.assertEqual(type(result[0][0]), dict)
            self.assertEqual(type(result), list)

            # verify backup by logs
            self.assertTrue(
                any(START_BACKUP_EXPECTED in line for line in cm.output),
                START_BACKUP_LOG_MSG,
            )

            self.assertTrue(
                any(COMPLETE_BACKUP_EXPECTED in line for line in cm.output),
                COMPLETE_BACKUP_LOG_MSG,
            )

    def test_send_request_exception(self):
        # Verifying all exception in send request call
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
        # Verifying sign on method with all exceptions
        _, host_dict = get_payload(self.testdata[1][0])
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
        # Verifying update_initparms by mocking send_request to get similar test data
        mock_func.side_effect = partial(mock_func_request, node=RESPONSE_DATA)
        res = update_initparam_details(self.init_data[0], self.fake_args.env)

        self.assertIn("Init Parms data has been updated successfully", res.text)
        self.assertEqual(res.status, True)

    def test_prepare_initparams_data_with_same_fileagent_status_onexecute(self):
        # Validate prepare initparms data method using same FA status and check the action
        # If same status then action will be SKIPPED otherwise UPDATED
        self.fake_args.execution_mode = EXECUTION_MODE[1]
        result, action = prepare_initparams_data(self.testdata[0][0], self.init_data[0], "y",
                                                 self.fake_args.execution_mode)
        self.assertEqual(result, self.init_data[0])
        self.assertEqual(action, FileAgentStatusEnum.SKIPPED)
        self.fake_args.execution_mode = EXECUTION_MODE[0]

    def test_prepare_initparams_data_with_diff_fileagent_status_onexecute(self):
        # Validate prepare initparms data method using diff FA status and check the action
        # If same status then action will be SKIPPED otherwise UPDATED
        self.fake_args.execution_mode = EXECUTION_MODE[1]
        result, action = prepare_initparams_data(self.testdata[1][0], self.init_data[4], "N",
                                                 self.fake_args.execution_mode)
        self.assertEqual(result, self.init_data[4])
        self.assertEqual(action, FileAgentStatusEnum.UPDATED)
        self.fake_args.execution_mode = EXECUTION_MODE[0]

    def test_prepare_initparams_data_with_invalid_fileagent_status_onexecute(self):
        # Validate prepare initparms data method using invalid FA status and check the action
        # If invalid status then action will be SKIPPED
        self.fake_args.execution_mode = EXECUTION_MODE[1]
        result, action = prepare_initparams_data(self.testdata[1][0], self.init_data[0], "abc",
                                                 self.fake_args.execution_mode)
        self.assertEqual(result, self.init_data[0])
        self.assertEqual(action, FileAgentStatusEnum.SKIPPED)
        self.fake_args.execution_mode = EXECUTION_MODE[0]

    def test_prepare_initparams_data_with_preview(self):
        # On preview mode, validating with unix data with same fileagent status
        result, action = prepare_initparams_data(self.testdata[0][0], self.init_data[1], "y",
                                                 self.fake_args.execution_mode)
        self.assertEqual(result, self.init_data[1])
        self.assertEqual(action, FileAgentStatusEnum.SKIP)

        # On preview mode, validating with windows data with same fileagent status
        result, action = prepare_initparams_data(self.testdata[1][0], self.init_data[2], "Y",
                                                 self.fake_args.execution_mode)
        self.assertEqual(result, self.init_data[2])
        self.assertEqual(action, FileAgentStatusEnum.SKIP)

        # On preview mode, validating with unix, windows data with Not mentioned status request
        result, action = prepare_initparams_data(self.testdata[1][0], self.init_data[2], None,
                                                 self.fake_args.execution_mode)
        self.assertEqual(result, self.init_data[2])
        self.assertEqual(action, FileAgentStatusEnum.SKIP)

    def test_format_tree_report(self):
        """
        Validate report data with table structure
        """
        global report_list
        result, action = prepare_initparams_data(self.testdata[0][0], self.init_data[1], "Y",
                                                 self.fake_args.execution_mode)
        self.assertEqual(result, self.init_data[1])
        self.assertEqual(action, FileAgentStatusEnum.SKIP)
        report = format_tree_report(report_list)
        self.assertEqual(len(report_list[-1]), 8)
        self.assertEqual(report_list[-1][1], HOST_DICT_1["node"])
        self.assertEqual(report_list[-1][2], HOST_DICT_1["hostname"])
        self.assertEqual(report_list[-1][3], HOST_DICT_1["os_type"])
        self.assertEqual(report_list[-1][4], UNIX_FA_KEY)
        self.assertEqual(report_list[-1][5], EXPECTED_PAYLOAD)
        self.assertIn(HOST_DICT_1["node"], report)
        self.assertIn(HOST_DICT_1["hostname"], report)
        self.assertIn(HOST_DICT_1["os_type"], report)
        self.assertIn(TABLE_TITLE, report)

    def test_format_tree_report_without_data(self):
        # Validate report if no data available
        report_list = []
        report = format_tree_report(report_list)
        self.assertIn(NO_DATA_MSG, report)

    def test_prerequisite_to_process_node(self):
        # Validate exeception if no data given
        with self.assertRaises(Exception) as cm:
            prerequisite_to_process_node({})
        self.assertIn(
            INCORRECT_NODE_EXCEPTION,
            str(cm.exception))

    def test_generate_report(self):
        # Validate generate report with Skip and update counter and msg
        with self.assertLogs(level='INFO') as cml:
            generate_report(self.fake_args.execution_mode, 2, 0, 0, 0, 1, 1, 13.81)
        self.assertTrue(any('Total execution duration: 13.81 seconds' in line for line in cml.output), NOT_FOUND, )
        self.assertTrue(any('Success: 2  Failed: 0  Skip:1   Update:1' in line for line in cml.output), NOT_FOUND, )
        self.assertTrue(any(
            INFO_MSG in line for line in
            cml.output), NOT_FOUND, )

        # Validate generate report with Skipped and updated counter and msg
        with self.assertLogs(level='INFO') as cml:
            generate_report('execute', 2, 0, 1, 1, 0, 0, 13.81)
        self.assertTrue(any('Total execution duration: 13.81 seconds' in line for line in cml.output), NOT_FOUND, )
        self.assertTrue(any('Success: 2  Failed: 0  Skipped:1   Updated:1' in line for line in cml.output),
                        NOT_FOUND, )
        self.assertTrue(any(
            INFO_MSG in line for line in
            cml.output),
            NOT_FOUND, )

    def test_fileagent_status_service_with_exception_onpreview(self):
        # validate exceptions if no node data process
        with self.assertRaises(Exception) as cm:
            failed_count = fileagent_status_service(None, self.fake_args)
        self.assertIn(
            GEN_EXCEPTION,
            str(cm.exception))

    def test_fileagent_status_service_with_unix_node_onpreview(self):
        # Validate fileagent status service SKIP status with unix node
        with patch("requests.Session.request") as mock_func:
            with patch("app.fileagent_status_app.send_request") as send_req:
                mock_func.side_effect = partial(mock_func_request, node=[self.testdata[0]])
                send_req.return_value = True, self.init_data[1]
                with self.assertLogs(level='INFO') as cml:
                    failed_count = fileagent_status_service([self.testdata[0]], self.fake_args)
                self.assertEqual(failed_count, 0)
                self.assertTrue(any(SKIP_STATUS_EXPECTED in line for line in cml.output),
                                NOT_FOUND, )
                self.assertTrue(any(PROCESS_START_MSG in line for line in cml.output), NOT_FOUND, )
                self.assertTrue(any(PROCESS_COMPLETED_MSG in line for line in cml.output), NOT_FOUND, )
                self.assertTrue(any(TABLE_TITLE in line for line in cml.output),
                                NOT_FOUND, )

    def test_fileagent_status_service_with_win_node_onpreview(self):
        # Validate fileagent status service skip status with windows node
        with patch("requests.Session.request") as mock_func:
            with patch("app.fileagent_status_app.send_request") as send_req:
                mock_func.side_effect = partial(mock_func_request, node=[self.testdata[1]])
                send_req.return_value = True, self.init_data[2]
                with self.assertLogs(level='INFO') as cml:
                    failed_count = fileagent_status_service([self.testdata[1]], self.fake_args)
                self.assertEqual(failed_count, 0)
                self.assertTrue(any(SKIP_STATUS_EXPECTED in line for line in cml.output),
                                NOT_FOUND, )
                self.assertTrue(any(PROCESS_START_MSG in line for line in cml.output), NOT_FOUND, )
                self.assertTrue(any(PROCESS_COMPLETED_MSG in line for line in cml.output), NOT_FOUND, )
                self.assertTrue(any(TABLE_TITLE in line for line in cml.output),
                                NOT_FOUND, )

    def test_fileagent_status_service_failed_with_unix_node_onpreview(self):
        # Validate fileagent status service failed with incorrect unix initparms data
        with patch("requests.Session.request") as mock_func:
            with patch("app.fileagent_status_app.send_request") as send_req:
                mock_func.side_effect = partial(mock_func_request, node=[self.testdata[0]])
                send_req.return_value = True, self.init_data[2]
                with self.assertLogs(level='INFO') as cml:
                    failed_count = fileagent_status_service([self.testdata[0]], self.fake_args)
                self.assertEqual(failed_count, 1)
                self.assertTrue(any(PROCESS_START_MSG in line for line in cml.output), NOT_FOUND, )
                self.assertTrue(any(PROCESS_FAILED_EXPECTED in line for line in cml.output),
                                PROCESS_FAILED_LOG_MSG, )
                self.assertTrue(any(TABLE_TITLE in line for line in cml.output),
                                NOT_FOUND, )

    def test_fileagent_status_service_failed_with_win_node_onpreview(self):
        # Validate fileagent status service UPDATE status with win node data
        with patch("requests.Session.request") as mock_func:
            with patch("app.fileagent_status_app.send_request") as send_req:
                mock_func.side_effect = partial(mock_func_request, node=[self.testdata[0]])
                send_req.return_value = True, self.init_data[3]
                with self.assertLogs(level='INFO') as cml:
                    failed_count = fileagent_status_service([self.testdata[0]], self.fake_args)
                self.assertEqual(failed_count, 0)
                self.assertTrue(any(UPDATE_STATUS_EXPECTED in line for line in cml.output),
                                NOT_FOUND, )
                self.assertTrue(any(PROCESS_START_MSG in line for line in cml.output), NOT_FOUND, )
                self.assertTrue(any(PROCESS_COMPLETED_MSG in line for line in cml.output),
                                NOT_FOUND, )
                self.assertTrue(any(TABLE_TITLE in line for line in cml.output),
                                NOT_FOUND, )

    def test_fileagent_status_service_with_same_status_onexecute(self):
        # Validate fileagent service with same FA status on execute mode
        self.fake_args.execution_mode = EXECUTION_MODE[1]
        with patch("requests.Session.request") as mock_func:
            with patch("app.fileagent_status_app.send_request") as send_req:
                mock_func.side_effect = partial(mock_func_request, node=[self.testdata[1]])
                send_req.return_value = True, self.init_data[4]
                with self.assertLogs(level='INFO') as cml:
                    failed_count = fileagent_status_service([self.testdata[1]], self.fake_args)

                self.assertEqual(failed_count, 0)
                self.assertTrue(any(
                    SAME_STATUS_MSG in line
                    for line in cml.output), NOT_FOUND, )
                self.assertTrue(any(PROCESS_COMPLETED_MSG in line for line in cml.output), NOT_FOUND, )
                self.assertTrue(any(TABLE_TITLE in line for line in cml.output),
                                NOT_FOUND, )
        self.fake_args.execution_mode = EXECUTION_MODE[0]

    def test_fileagent_status_service_with_different_status_onexecute(self):
        # Validate fileagent service with diff FA status on execute mode
        self.fake_args.execution_mode = EXECUTION_MODE[1]
        with patch("requests.Session.request") as mock_func:
            with patch("app.fileagent_status_app.send_request") as send_req:
                mock_func.side_effect = partial(mock_func_request, node=[self.testdata[2]])
                send_req.return_value = True, RESPONSE_DATA
                with self.assertLogs(level='INFO') as cml:
                    failed_count = fileagent_status_service([self.testdata[2]], self.fake_args)

                self.assertEqual(failed_count, 0)
                self.assertTrue(any(UPDATE_STATUS_MSG in line for line in cml.output),
                                NOT_FOUND, )
                self.assertTrue(any(UPDATED_STATUS_MSG in line for line in cml.output),
                                NOT_FOUND, )
                self.assertTrue(any(PROCESS_COMPLETED_MSG in line for line in cml.output), NOT_FOUND, )
                self.assertTrue(any(TABLE_TITLE in line for line in cml.output),
                                NOT_FOUND, )
        self.fake_args.execution_mode = EXECUTION_MODE[0]

    def test_fileagent_status_service_with_update_failed_status_onexecute(self):
        # Validate fileagent service with status update failed on execute mode
        self.fake_args.execution_mode = EXECUTION_MODE[1]
        with patch("requests.Session.request") as mock_func:
            with patch("app.fileagent_status_app.send_request") as send_req:
                with patch("app.fileagent_status_app.update_initparam_details") as uip:
                    mock_func.side_effect = partial(mock_func_request, node=[self.testdata[2]])
                    send_req.return_value = True, self.init_data[0]
                    uip.return_value = False, RESPONSE_DATA
                    with self.assertLogs(level='INFO') as cml:
                        failed_count = fileagent_status_service([self.testdata[2]], self.fake_args)

                    self.assertEqual(failed_count, 0)
                    self.assertTrue(any(UPDATE_FAILED_EXPECTED in line for line in cml.output),
                                    NOT_FOUND, )
                    self.assertTrue(any(TABLE_TITLE in line for line in cml.output),
                                    NOT_FOUND, )

        self.fake_args.execution_mode = EXECUTION_MODE[0]
