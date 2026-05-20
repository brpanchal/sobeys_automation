import unittest
from app.services.b2bi_service import B2BIService, _load_codelist_from_json
from app.models.b2b_codelist_entry import B2BCodeListEntry
from app.models.b2bi import B2BI
from dotenv import load_dotenv
from unittest.mock import patch, MagicMock
from functools import partial
from tests.constants import *
from tests.helper import *
import logging

logger = logging.getLogger(__name__)

class TestB2BIService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load .env only once for the whole test class (faster, less noise)
        load_dotenv()
        cls.b2bi = B2BI()

    def setUp(self):
        # Fresh service and baseline config per tests
        self.services = B2BIService({})
        self.services.deploy_flag = ''
        self.services.execution_mode = EXECUTION_TYPE[0]
        self.services.env = ENV
        self.b2bi.delivery_cd = read_test_data("DELIVERY_CD_PAYLOAD")
        self.b2bi.identify_consumer = read_test_data("DELIVERY_PAYLOAD")
        self.b2bi.delivery_gen = read_test_data("DELIVERY_PAYLOAD")
        self.b2bi.delivery_sftp = read_test_data("DELIVERY_PAYLOAD")
        self.b2bi.delivery_wsmq = read_test_data("DELIVERY_PAYLOAD")
        self.b2bi.delivery_filesystem = read_test_data("DELIVERY_PAYLOAD")
        self.b2bi.delivery_db = read_test_data("DELIVERY_PAYLOAD")
        self.b2bi.delivery_azure_filestorage = read_test_data("DELIVERY_PAYLOAD")
        self.b2bi.collect_sftp = read_test_data("DELIVERY_PAYLOAD")
        self.b2bi.delivery_email = read_test_data("DELIVERY_PAYLOAD")
        self.del_cd_getlist = read_test_data("GET_DELIVERY_CD_LIST")
        self.del_cons_getlist = read_test_data("GET_DELIVERY_CONSUMER_LIST")

    def get_codelist(self, codelist_json):
        json_data = codelist_json[0]
        codes = [B2BCodeListEntry(**code) for code in json_data.get("codes")]
        return codes

    def test_deploy_delivery_consumer_preview(self):
        """Verifying deploy delivery consumer in preview mode"""
        logger.info("Running test_deploy_delivery_consumer...")
        with patch("requests.Session.request") as mq:
            with self.assertLogs(level="INFO") as cm:
                mq.side_effect = partial(mock_func_request, node=self.del_cons_getlist)
                self.services.deploy_identify_consumer(self.b2bi.identify_consumer)
            self.assertIn(f"{CONSUMER_CODE_LIST} completed.", str(cm.output))
        logger.info("Test test_deploy_delivery_consumer is passed successfully")

    def test_deploy_delivery_consumer_insert(self):
        """Verifying deploy delivery consumer in execution mode"""
        logger.info("Running test_deploy_delivery_consumer...")
        with patch("requests.Session.request") as mq:
                with self.assertLogs(level="DEBUG") as cq:
                    mq.side_effect = partial(mock_func_request, node=self.del_cons_getlist)
                    self.services.execution_mode = EXECUTION_TYPE[1]
                    self.services.deploy_identify_consumer(self.b2bi.delivery_cd)
                    self.services.execution_mode = EXECUTION_TYPE[0]
                self.assertIn(f"Inserting codelist entry for", str(cq.output))
                self.assertIn(f"Codelist entry created successfully", str(cq.output))

        logger.info("Test test_deploy_delivery_consumer is passed successfully")

    def test_deploy_delivery_consumer_with_empty_getcodelist(self):
        """Verifying deploy delivery consumer exception while getting codelist empty from server"""
        logger.info("Running test_deploy_delivery_consumer_with_empty_list...")
        with patch("requests.Session.request") as mq:
            with self.assertRaises(Exception) as cm:
                mq.side_effect = partial(mock_func_request)
                self.services.deploy_identify_consumer(self.b2bi.identify_consumer)
            self.assertIn(f"Unexpected error while fetching codelist {CONSUMER_CODE_LIST}:", str(cm.exception))
        logger.info("Test test_deploy_delivery_consumer_with_empty_list is passed successfully")

    def test_deploy_delivery_consumer_with_empty_codelist(self):
        """Verifying deploy delivery consumer exception while getting codelist empty"""
        logger.info("Running test_deploy_delivery_consumer_with_empty_codelist...")
        with patch("requests.Session.request") as mq:
            with self.assertNoLogs(level="INFO"):
                mq.side_effect = partial(mock_func_request, node=self.del_cons_getlist)
                self.services.deploy_identify_consumer(None)

        #Passing empty codelist to verify the no codelist found log
        with patch("app.services.b2bi_service.B2BIService.get_codelist_records_from_b2bi") as mock:
            with self.assertLogs(level="DEBUG") as ctx:
                mock.return_value = None
                self.services.deploy_identify_consumer(self.b2bi.identify_consumer)

            self.assertIn("*** No codelist found ***", str(ctx.output))

        logger.info("Test test_deploy_delivery_consumer_with_empty_codelist is passed successfully")

    def test_deploy_delivery_cd_preview(self):
        """Verifying deploy delivery cd while running in preview mode"""
        logger.info("Running test_deploy_delivery_cd...")
        with patch("requests.Session.request") as mq:
            with self.assertLogs(level="INFO") as cm:
                mq.side_effect = partial(mock_func_request, node=self.del_cd_getlist)
                self.services.deploy_delivery_cd(self.b2bi.delivery_cd)
            self.assertIn(f"{CD_CODE_LIST} completed.", str(cm.output))
        logger.info("Test test_deploy_delivery_cd is passed successfully")

    def test_deploy_delivery_cd_with_empty_getcodelist(self):
        """Verifying deploy delivery cd exception while getting codelist empty from server"""
        logger.info("Running test_deploy_delivery_cd_with_empty_list...")
        with patch("requests.Session.request") as mq:
            with self.assertRaises(Exception) as cm:
                mq.side_effect = partial(mock_func_request)
                self.services.deploy_delivery_cd(self.b2bi.delivery_cd)
            self.assertIn(f"Unexpected error while fetching codelist {CD_CODE_LIST}:", str(cm.exception))
        logger.info("Test test_deploy_delivery_cd_with_empty_list is passed successfully")

    def test_deploy_delivery_cd_with_empty_codelist(self):
        """Verifying deploy delivery cd exception while getting codelist empty"""
        logger.info("Running test_deploy_delivery_cd_with_empty_codelist...")
        with patch("requests.Session.request") as mq:
            with self.assertNoLogs(level="INFO"):
                mq.side_effect = partial(mock_func_request, node=self.del_cd_getlist)
                self.services.deploy_delivery_cd(None)
        logger.info("Test test_deploy_delivery_cd_with_empty_codelist is passed successfully")

    def test_getcodelist_exception(self):
        """ Verifying all exception in send request call"""
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='HTTPError')
            with self.assertRaises(Exception) as ctx:
                self.services.get_codelist(None)

            self.assertIn(B2BI_HTTP_ERROR, str(ctx.exception))

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='RequestException')
            with self.assertRaises(Exception) as ctx:
                self.services.get_codelist("TEST01")

            self.assertIn(B2BI_REQ_EXCEPTION, str(ctx.exception))

    def test_create_codelist_exception(self):
        # Verifying all exception in create codelist request call
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='HTTPError')
            with self.assertRaises(Exception) as ctx:
                self.services.create_codelist("", self.b2bi.identify_consumer, "")

            self.assertIn("Failed to insert codelist entry. Status code:", str(ctx.exception))
            self.assertIn("Unexpected error while inserting codelist entry for", str(ctx.exception))

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='RequestException')
            with self.assertRaises(Exception) as ctx:
                self.services.create_codelist("", self.b2bi.identify_consumer, "")

            self.assertIn(B2BI_INSERT_REQ_EXCEPTION, str(ctx.exception))

    def test_remove_codelist_exception(self):
        # Verifying all exception in remove codelist request call
        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='HTTPError')
            with self.assertRaises(Exception) as ctx:
                self.services.remove_codelist("", self.b2bi.identify_consumer)

            self.assertIn("Failed to remove codelist entry. Status code:", str(ctx.exception))
            self.assertIn("Unexpected error while remove codelist entry for", str(ctx.exception))

        with patch("requests.Session.request") as mq:
            mq.side_effect = partial(mock_excep_request, param='RequestException')
            with self.assertRaises(Exception) as ctx:
                self.services.remove_codelist("", self.b2bi.identify_consumer)

            self.assertIn(B2BI_REMOVE_REQ_EXCEPTION, str(ctx.exception))

    def test_match_codelist_with_b2bi_codelist(self):
        """Verifying given codelist match in getcodelist entry"""
        #If given codelist match in getcodelist entry
        identify_cons_obj = self.get_codelist(self.b2bi.identify_consumer)[0]
        get_cons_obj = [_load_codelist_from_json(self.del_cons_getlist)]
        result = self.services.match_codelist_with_b2bi_codelist(get_cons_obj[0].codes, identify_cons_obj)
        self.assertEqual(result, [identify_cons_obj])

        #If given codelist not match in codelist entry
        identify_cons_obj = self.get_codelist(self.b2bi.delivery_cd)[0]
        get_cons_obj = [_load_codelist_from_json(self.del_cons_getlist)]
        result = self.services.match_codelist_with_b2bi_codelist(get_cons_obj[0].codes, identify_cons_obj)
        self.assertEqual(result, [])

        # If given codelist partial match in codelist entry
        identify_cons_obj = self.get_codelist(self.b2bi.identify_consumer)[0]
        identify_cons_obj.text3 = "text3"
        get_cons_obj = [_load_codelist_from_json(self.del_cons_getlist)]
        result = self.services.match_codelist_with_b2bi_codelist(get_cons_obj[0].codes, identify_cons_obj)
        self.assertEqual(result, [])

    def test_deploy_delivery_consumer_remove(self):
        """Verifying remove delivery consumer"""
        logger.info("Running test_deploy_delivery_consumer_remove...")
        with patch("requests.Session.request") as mq:
            with self.assertLogs(level="INFO") as cm:
                mq.side_effect = partial(mock_func_request, node=self.del_cons_getlist)
                self.services.deploy_flag = 'Remove'
                self.services.deploy_identify_consumer(self.b2bi.identify_consumer)
                self.services.deploy_flag = ''
            self.assertIn(f"{CONSUMER_CODE_LIST} completed.", str(cm.output))
            self.assertIn(f"Codelist entry to be removed:", str(cm.output))

            with self.assertLogs(level="INFO") as cm:
                mq.side_effect = partial(mock_func_request, node=self.del_cons_getlist)
                self.services.deploy_flag = 'Remove'
                self.services.execution_mode = EXECUTION_TYPE[1]
                self.services.deploy_identify_consumer(self.b2bi.identify_consumer)
                self.services.deploy_flag = ''
                self.services.execution_mode = EXECUTION_TYPE[0]
            self.assertIn(f"{CONSUMER_CODE_LIST} completed.", str(cm.output))
            self.assertIn(f"Codelist ({CONSUMER_CODE_LIST}) entry removed successfully with payload:", str(cm.output))
        logger.info("Test test_deploy_delivery_consumer_remove is passed successfully")

    def test_deploy_b2b_artifacts(self):
        """Verifying deploy b2b artifacts including all codelist"""
        with patch("requests.Session.request") as mq:
            with self.assertLogs(level="INFO") as cm:
                mq.side_effect = partial(mock_func_request, node=self.del_cons_getlist)
                self.services.deploy_b2b_artifacts(self.b2bi, self.services.env, "Process", deploy_flag='')

            self.assertIn(f"Process B2BI artifacts...", str(cm.output))
            self.assertIn(f"{CONSUMER_CODE_LIST} completed.", str(cm.output))
            self.assertIn(f"{CD_CODE_LIST} completed.", str(cm.output))
            self.assertIn(f"{GEN_CODE_LIST} completed.", str(cm.output))
            self.assertIn(f"{WSMQ_CODE_LIST} completed.", str(cm.output))
            self.assertIn(f"{EMAIL_CODE_LIST} completed.", str(cm.output))
            self.assertIn(f"{SFTP_CODE_LIST} completed.", str(cm.output))
            self.assertIn(f"{DB_CODE_LIST} completed.", str(cm.output))


if __name__ == "__main__":
    unittest.main()
