import unittest
from unittest.mock import patch, MagicMock
from functools import partial
import json
from tests.constants import *
from tests.helper import *
from cert_app import *
import  logging


logger = logging.getLogger(__name__)

class TestCertApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load .env only once for the whole test class (faster, less noise)
        load_dotenv()
        cls.node_data = read_file(FILENAME, TEST_DATA_PATH, True)
        cls.cert = cls.read_any_file(CERT_FILENAME)
        with patch('cert_app.read_file', return_value=cls.cert):
            cls.cert_data = read_certificates()

    def setUp(self):
        # Common fake args object
        self.fake_args = MagicMock()
        self.fake_args.env = "qa"
        self.fake_args.execution_mode = "preview"

    @staticmethod
    def read_any_file(file_name):
        cond = os.path.splitext(file_name)[1] != ""
        filename =  file_name if cond else f"{file_name}.json"
        with open(os.path.join(TEST_DATA_PATH, filename), "r") as read_file:
            return read_file.read() if cond else json.load(read_file)

    def test_read_file_without_file(self):
        res = read_file(None, None)
        self.assertEqual(res, None)

    def test_read_file_with_filedata(self):
        if len(self.node_data) > 0:
            self.assertListEqual(list(self.node_data[0].keys()), NODE_LIST, "Not matched keys with data received from file")

    def test_read_certificates(self):
        with patch('cert_app.read_file', return_value=self.cert):
            cert_list = read_certificates()
            self.assertEqual(len(cert_list), 3, "Didn't get all 3 list of nodes based on os_type")
            self.assertTrue(isinstance(cert_list, dict))
            self.assertTrue(isinstance(cert_list['windows_cert'], str))

    def test_read_certificates_exception(self):
        with patch('cert_app.read_file') as rf:
            rf.side_effect = partial(mock_cert_exception)
            with self.assertRaises(Exception) as cm:
                read_certificates()
            self.assertIn('Error reading certificate file', str(cm.exception))

    def test_read_node_list_json_data(self):
        with patch("cert_app.read_file", return_value=self.node_data):
            node_list = read_node_list_json()
            self.assertTrue(isinstance(node_list[1], list))
            self.assertTrue(isinstance(node_list[1][0], dict))
            self.assertTrue(isinstance(node_list, list))

    def test_read_node_list_json_with_exception(self):
        with patch("cert_app.read_file", return_value=None):
            with self.assertRaises(Exception) as cm:
                read_node_list_json()

            self.assertIn(FILE_ERROR, str(cm.exception), "Not Received exception error to validate")


    @patch("sys.argv", ["prog", "--env", "dev", "--execution-mode", "preview"])
    def test_parser_preview_mode(self):
        args = input_parser()
        self.assertEqual(args.env, "dev")
        self.assertEqual(args.execution_mode, "preview")

    @patch("sys.argv", ["prog", "--env", "qa", "--execution-mode", "execute"])
    def test_parser_execute_mode(self):
        args = input_parser()
        self.assertEqual(args.env, "qa")
        self.assertEqual(args.execution_mode, "execute")

    @patch("sys.argv", ["prog", "--env", "prod", "--execution-mode", "preview"])
    def test_parser_default_execution_mode(self):
        args = input_parser()
        self.assertEqual(args.env, "prod")
        self.assertEqual(args.execution_mode, "preview")

    def test_missing_required_arguments(self):
        with self.assertRaises(SystemExit):  # argparse exits on missing required args
            with patch("sys.argv", ["prog"]):
                input_parser()

    @patch("cert_app.run_cert_service")
    @patch("cert_app.read_file")
    @patch("cert_app.logger")
    @patch("cert_app.input_parser")
    def test_main_happy_path(self, mock_input_parser, mock_logger, read_file_data, mock_run_service):
        # Arrange
        mock_input_parser.return_value = self.fake_args
        mock_run_service.return_value = None
        read_file_data.side_effect = partial(mock_read_file, node=self.node_data, cert=self.cert)
        main()

        # Assert
        mock_input_parser.assert_called_once()
        mock_logger.info.assert_any_call(
            "========== Loading required configuration started ============="
        )
        mock_logger.info.assert_any_call(
            "========== Loading required configuration completed ============="
        )

        # Completion logs should be written in finally
        mock_logger.info.assert_any_call("========== Certificate update completed ==========")

        # Ensure the start banner contains env and mode
        # (Use call_args_list to check formatted f-string without tightly coupling entire string)
        start_log_calls = [c for c in mock_logger.info.call_args_list if "Certificate update started" in c.args[0]]
        self.assertTrue(start_log_calls, "Start banner log not found")
        self.assertIn("Env=qa", start_log_calls[0].args[0])
        self.assertIn("Execution mode=preview", start_log_calls[0].args[0])

    @patch("cert_app.run_cert_service", side_effect=RuntimeError("boom"))
    @patch("cert_app.read_node_list_json", return_value={"nodes": []})
    @patch("cert_app.logger")
    @patch("cert_app.input_parser")
    def test_main_wraps_exceptions(self, mock_input_parser, mock_logger, mock_read_node_list_json, mock_run_service):
        # Arrange
        mock_input_parser.return_value = self.fake_args
        mock_run_service.side_effect = partial(mock_cert_exception)
        with self.assertRaises(Exception) as ctx:
            with patch("cert_app.read_file", node=self.node_data, cert=self.cert):
                main()

        self.assertIn("Unexpected exception found during execution: boom", str(ctx.exception))

        # Finally block should still log completion banners
        mock_logger.info.assert_any_call("========== Certificate update completed ==========")

        # Ensure config load still happened before the crash in service
        mock_read_node_list_json.assert_called_once()

    @patch("cert_app.run_cert_service", side_effect=ValueError("service error"))
    @patch("cert_app.read_node_list_json", return_value={"nodes": ["x"]})
    @patch("cert_app.logger")
    @patch("cert_app.input_parser")
    def test_main_finally_always_runs(self, mock_input_parser, mock_logger, *_):
        # Arrange
        mock_input_parser.return_value = self.fake_args
        with patch("cert_app.read_file", node=self.node_data, cert=self.cert):
            with self.assertRaises(Exception):
                main()

        # Assert that completion logs were emitted despite exception
        mock_logger.info.assert_any_call("========== Certificate update completed ==========")




