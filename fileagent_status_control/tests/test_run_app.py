import unittest
from unittest.mock import patch, MagicMock
from functools import partial
import json
from tests.constants import *
from tests.helper import *
from run_app import *
import logging


logger = logging.getLogger(__name__)

class TestRunApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load .env only once for the whole test class (faster, less noise)
        load_dotenv()
        cls.data = read_file(FILENAME, TEST_DATA_PATH, True)
        cls.node_data = []
        for node in cls.data:
            cls.node_data.append([node])

    def setUp(self):
        # Common fake args object
        self.fake_args = MagicMock()
        self.fake_args.env = "qa"
        self.fake_args.execution_mode = "preview"

    def test_read_file_without_file(self):
        res = read_file(None, None)
        self.assertEqual(res, None)

    def test_read_file_with_filedata(self):
        if len(self.node_data) > 0:
            self.assertListEqual(list(self.node_data[0][0].keys()), NODE_LIST, "Not matched keys with data received from file")

    def test_read_node_list_json_data(self):
        with patch("run_app.read_file", return_value=self.data):
            node_list = read_node_list_json()
            self.assertTrue(isinstance(node_list[1], list))
            self.assertTrue(isinstance(node_list[1][0], dict))
            self.assertTrue(isinstance(node_list, list))

    def test_read_node_list_json_with_exception(self):
        with patch("run_app.read_file", return_value=None):
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

    @patch("run_app.fileagent_status_service")
    @patch("run_app.read_file")
    @patch("run_app.logger")
    @patch("run_app.input_parser")
    def test_main_function_success(self, mock_input_parser, mock_logger, read_file_data, mock_run_service):
        # Arrange
        mock_input_parser.return_value = self.fake_args
        mock_run_service.return_value = 0
        read_file_data.side_effect = partial(mock_read_file, node=self.node_data)

        with patch("sys.exit") as mock_exit:
            main()
            mock_exit.assert_called_once_with(0)

        # Assert
        mock_input_parser.assert_called_once()
        mock_logger.info.assert_any_call(
            "========== Loading required configuration started ============="
        )
        mock_logger.info.assert_any_call(
            "========== Loading required configuration completed ============="
        )

        mock_logger.info.assert_any_call(
            "========== CD Enable Disable file agent status process completed =========="
        )

        # Ensure the start banner contains env and mode
        # (Use call_args_list to check formatted f-string without tightly coupling entire string)
        start_log_calls = [c for c in mock_logger.info.call_args_list if "CD Enable Disable file agent status process started" in c.args[0]]
        self.assertTrue(start_log_calls, "Start banner log not found")
        self.assertIn("Env=qa", start_log_calls[0].args[0])
        self.assertIn("Execution mode=preview", start_log_calls[0].args[0])

    @patch("run_app.fileagent_status_service")
    @patch("run_app.read_file")
    @patch("run_app.logger")
    @patch("run_app.input_parser")
    def test_main_function_failed(self, mock_input_parser, mock_logger, read_file_data, mock_run_service):
        # Arrange
        mock_input_parser.return_value = self.fake_args
        mock_run_service.return_value = 2
        read_file_data.side_effect = partial(mock_read_file, node=self.node_data)

        with patch("sys.exit") as mock_exit:
            main()
            mock_exit.assert_called_once_with(1)

        # Assert
        mock_input_parser.assert_called_once()
        mock_logger.info.assert_any_call(
            "========== Loading required configuration started ============="
        )
        mock_logger.info.assert_any_call(
            "========== Loading required configuration completed ============="
        )

        mock_logger.info.assert_any_call(
            "========== CD Enable Disable file agent status process completed =========="
        )

    @patch("run_app.fileagent_status_service", side_effect=RuntimeError("boom"))
    @patch("run_app.read_node_list_json", return_value={"nodes": []})
    @patch("run_app.logger")
    @patch("run_app.input_parser")
    def test_main_wraps_exceptions(self, mock_input_parser, mock_logger, mock_read_node_list_json, mock_run_service):
        # Arrange
        mock_input_parser.return_value = self.fake_args
        mock_run_service.side_effect = partial(mock_run_exception)
        with self.assertRaises(Exception) as ctx:
            with patch("run_app.read_file", node=self.node_data):
                with patch("sys.exit") as mock_exit:
                    main()

        self.assertIn("Unexpected exception found during execution: boom", str(ctx.exception))

        # Finally block should still log completion banners
        mock_logger.info.assert_any_call("========== CD Enable Disable file agent status process completed ==========")

        # Ensure config load still happened before the crash in service
        mock_read_node_list_json.assert_called_once()

    @patch("run_app.fileagent_status_service", side_effect=ValueError("service error"))
    @patch("run_app.read_node_list_json", return_value={"nodes": ["x"]})
    @patch("run_app.logger")
    @patch("run_app.input_parser")
    def test_main_finally_always_runs(self, mock_input_parser, mock_logger, *_):
        # Arrange
        mock_input_parser.return_value = self.fake_args
        with patch("run_app.read_file", node=self.node_data):
            with self.assertRaises(Exception):
                with patch("sys.exit") as mock_exit:
                    main()

        # Assert that completion logs were emitted despite exception
        mock_logger.info.assert_any_call("========== CD Enable Disable file agent status process completed ==========")




