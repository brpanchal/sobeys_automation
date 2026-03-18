import unittest
from unittest.mock import patch, MagicMock
from functools import partial
from tests.constants import *
from tests.helper import *
from tests.test_run_app import TestRunApp
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

    def setUp(self):
        # Common fake args object
        self.fake_args = MagicMock()
        self.fake_args.env = ENV
        self.fake_args.execution_mode = EXECUTION_MODE
        self.fake_args.base_url = BASE_URL
        self.fake_args.host_dict = {}

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
            mq.side_effect = partial(mock_request, node=node_data)
            result = get_initparam_details(self.fake_args.env, json_type=True)
            self.assertEqual(type(result[0][0]), dict)
            self.assertEqual(type(result), list)
            self.assertGreater(len(result), 0)
            self.assertEqual(result, node_data)

    def test_get_certificate_backup(self):
        with patch("requests.Session.request") as mq:
            node_data =  [[{ 'fileagent.enable': EXPECTED_PAYLOAD}]]
            mq.side_effect = partial(mock_request, node=node_data)
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



