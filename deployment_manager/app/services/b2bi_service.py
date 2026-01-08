import logging
import os
import requests
import urllib3
from requests.auth import HTTPBasicAuth
from app.models.b2b_codelist import B2BCodelist
from app.models.b2b_codelist_entry import B2BCodeListEntry
from dotenv import load_dotenv
from app.models.b2bi import B2BI

logger = logging.getLogger(__name__)
load_dotenv()

def _load_codelist_from_json(codelist_json: dict) -> B2BCodelist | None:
    if codelist_json:
        json_data = codelist_json[0]
        codes = [B2BCodeListEntry(**code) for code in json_data.get("codes")]
        return B2BCodelist(
            id=json_data["_id"],
            codeListName=json_data["codeListName"],
            versionNumber=json_data["versionNumber"],
            createDate=json_data["createDate"],
            userName=json_data["userName"],
            listStatus=json_data["listStatus"],
            codes=codes
        )
    return None


class B2BIService:
    def __init__(self, codelist_dict):
        self.session = requests.Session()
        self.version_id = None
        self.username = None
        self.password = None
        self.url = None
        self.execution_mode = None
        self.env = None
        self.codelist_dict = codelist_dict

    def match_codelist_with_b2bi_codelist(self, execution_codelist, codelist_entry):
        """
        :param codelist_entry: entry tobe find or search in self.codes
        :return:
        Here require to collect all consumers of existing entry and new entry, sort the list and compare it.
        * There is a chance that single consumer could be there for existing entry and multiple consumers in new entry
            Ex: existing_entry{                             new_entry{
                    senderCode: sender1,                        senderCode: sender2,
                    receiverCode: receiver1,                    receiverCode: receiver2,
                    description: consumer0,                     description: consumer0,
                    text1: "",                                  text1: Consumer1,
                    text2: ""                                   text2: Consumer2,
                    text3: ""                                   text3: "",
                    ....                                        ...
                    }                                           }
        * For multiple consumers in existing entry but they are not in order with new entry, consumer list needs to be
             sorted before compare it.
            Ex:existing_entry{                             new_entry{
                    senderCode: sender1,                        senderCode: sender2,
                    receiverCode: receiver1,                    receiverCode: receiver2,
                    description: consumer1,                     description: consumer0,
                    text1: Consumer0,                           text1: Consumer1,
                    text2: Consumer2,                           text2: Consumer2,
                    text3: ""                                   text3: "",
                    ....                                        ...
                    }                                           }
        """
        for entry in execution_codelist:
            # Check SenderCode and ReceiverCode match
            if entry.senderCode == codelist_entry.senderCode and entry.receiverCode == codelist_entry.receiverCode and entry.description == codelist_entry.description:
                """
                compare other fields only if senderCode and receiverCode matches
                """
                for i in range(1, 10):
                    if getattr(entry, f"text{i}") != getattr(codelist_entry, f"text{i}"):
                        break
                else:
                    return [entry]
        return []

    # Populate Codelist Generalised method for populate codelist from B2BI
    def get_codelist(self, codelist_name):
        url = None  # keep reference for debugging/logging in finally
        res = {}
        codelist_records = {}
        try:
            # Build API URL
            codelist_api = f"{self.url}{os.getenv("B2BI_CODELIST")}"
            query_params = f"?_range=0-999&codeListName={codelist_name}&listStatus=1"
            url = codelist_api + query_params
            logger.debug(f"Getting codelist {codelist_name} at {url}")

            username = self.username
            password = self.password

            headers = {"Accept": "application/json"}

            # Make the GET request
            urllib3.disable_warnings()
            response = requests.get(url, headers=headers, auth=HTTPBasicAuth(username, password), verify=False)

            # Success case
            if response.status_code == 200:
                res = response.json()
                logger.debug("Codelist retrieved successfully")

                codelist_records = _load_codelist_from_json(res)
                message = f"Total records = {len(codelist_records.codes)}"
                logger.debug(message)

            else:
                logger.debug(f"Failed to retrieve codelist. Status code: {response.status_code}")
                logger.debug(response.text)
                raise Exception(f"Failed to retrieve codelist. Status code: {response.status_code}")
        except requests.exceptions.RequestException as req_err:
            # Handles network, timeout, connection issues
            logger.error(f"Request error while fetching codelist {codelist_name}: {req_err}")
            raise Exception(f"Request error while fetching codelist {codelist_name}: {req_err}")
        except Exception as e:
            # Handles unexpected issues (JSON decode, etc.)
            logger.error(f"Unexpected error while fetching codelist {codelist_name}: {e}")
            raise Exception(f"Unexpected error while fetching codelist {codelist_name}: {e}")
        #finally:
        #    logger.debug(f"Finished execution of get_codelist for {codelist_name}. URL: {url}")
        return codelist_records

    def get_codelist_records_from_b2bi(self, codelist_name):
        if not (codelist_name in self.codelist_dict):
            logger.debug(f"Fetching b2bi codelist for {codelist_name}")
            codelist_data = self.get_codelist(codelist_name)
            self.codelist_dict[codelist_name] = codelist_data

        return self.codelist_dict[codelist_name]

    def deploy_identify_consumer(self, identify_consumer_obj):
        codelist_name = os.getenv("B2BI_CODELIST_SBYS_FW_IDENTIFY_CONSUMER")
        logger.info(f"{codelist_name} starting")
        if identify_consumer_obj:
            logger.debug(f"*** Building {codelist_name} Codelist")
            execution_result = self.get_codelist_records_from_b2bi(codelist_name)
            consumer_codes = [B2BCodeListEntry(**code) for code in identify_consumer_obj.get("codes")]

            if execution_result:
                # codelist entries found
                cl = execution_result
                matches = self.match_codelist_with_b2bi_codelist(cl.codes, consumer_codes[0])
                logger.debug("Matches = %s", matches)
                if len(matches) > 0:
                    logger.info(f"Found {len(matches)} matches for codelist {consumer_codes[0]} and Skipping")
                else:
                    logger.debug(f"Inserting codelist entry {consumer_codes[0]}")
                    json_object = consumer_codes[0].to_dict()
                    self.insert_cl_sbys_delivery_codelist(cl.id, json_object, codelist_name)
            else:
                logger.debug("*** No codelist found ***")
        logger.info(f"{codelist_name} completed.")

    def fetch_and_build_codelist(self, codelist_name, codelist):
        if codelist:
            logger.info(f"{codelist_name} starting")
            logger.debug(f"*** Building {codelist_name} Codelist")

            execution_result = self.get_codelist_records_from_b2bi(codelist_name)
            consumer_codes = [
                B2BCodeListEntry(**code)
                for obj in codelist
                for code in obj.get("codes", [])
            ]

            if execution_result:
                cl = execution_result
                for consumer_code in consumer_codes:
                    logger.debug("id = %s, Name = %s, Codes size = %s", cl.id, cl.codeListName, len(cl.codes))
                    matches = self.match_codelist_with_b2bi_codelist(cl.codes, consumer_code)
                    if len(matches) > 0:
                        logger.info(f"Found {len(matches)} matches for codelist {consumer_code} and Skipping")
                    else:
                        logger.debug(f"Inserting codelist entry {consumer_code}")
                        json_object = consumer_code.to_dict()
                        self.insert_cl_sbys_delivery_codelist(cl.id, json_object, codelist_name)
            else:
                logger.debug("*** No codelist found ***")
            logger.info(f"{codelist_name} completed.")

    def deploy_delivery_cd(self, delivery_sftp_obj):
        codelist_name = os.getenv("B2BI_CODELIST_SBYS_FW_DELIVERY_CD")
        self.fetch_and_build_codelist(codelist_name, delivery_sftp_obj)

    def deploy_delivery_gen(self, delivery_sftp_obj):
        codelist_name = os.getenv("B2BI_CODELIST_SBYS_FW_DELIVERY_GEN")
        self.fetch_and_build_codelist(codelist_name, delivery_sftp_obj)

    def deploy_delivery_sftp(self, delivery_sftp_obj):
        codelist_name = os.getenv("B2BI_CODELIST_SBYS_FW_DELIVERY_SFTP")
        self.fetch_and_build_codelist(codelist_name, delivery_sftp_obj)

    def deploy_delivery_wsmq(self, delivery_wsmq_obj):
        codelist_name = os.getenv("B2BI_CODELIST_SBYS_FW_DELIVERY_WSMQ")
        self.fetch_and_build_codelist(codelist_name, delivery_wsmq_obj)

    def deploy_delivery_filesystem(self, delivery_filesystem_obj):
        codelist_name = os.getenv("B2BI_CODELIST_SBYS_FW_DELIVERY_FILESYSTEM")
        self.fetch_and_build_codelist(codelist_name, delivery_filesystem_obj)

    def deploy_delivery_db(self, delivery_db_obj):
        codelist_name = os.getenv("B2BI_CODELIST_SBYS_FW_DELIVERY_DB")
        self.fetch_and_build_codelist(codelist_name, delivery_db_obj)

    def deploy_delivery_azurefilestrorage(self, delivery_azurefilestrorage_obj):
        codelist_name = os.getenv("B2BI_CODELIST_SBYS_FW_DELIVERY_AZUREFILESTORAGE")
        self.fetch_and_build_codelist(codelist_name, delivery_azurefilestrorage_obj)

    def deploy_collect_sftp(self, delivery_sftp_obj):
        codelist_name = os.getenv("B2BI_CODELIST_SBYS_FW_COLLECT_SFTP")
        self.fetch_and_build_codelist(codelist_name, delivery_sftp_obj)

    def deploy_delivery_email(self, delivery_email):
        codelist_name = os.getenv("B2BI_CODELIST_SBYS_FW_EMAIL")
        self.fetch_and_build_codelist(codelist_name, delivery_email)

    def insert_cl_sbys_delivery_codelist(self, cl_id, payload, codelist_name):
        if self.is_preview():
            msg = f"Codelist entry not found. Proposed entry for insertion:"
            logger.debug(msg)
            return None
        else:
            result = self.create_codelist(cl_id, payload, codelist_name)
            return result

    def is_preview(self):
        return self.execution_mode.lower() == "preview"

    def create_codelist(self, cl_id, payload, codelist_name):
        url = None  # keep reference for debugging/logging in finally
        execution_result = None

        try:
            # Build API URL
            codelist_api = f"{self.url}{os.getenv("B2BI_CODELIST")}"
            query_params = f"{cl_id}/actions/bulkupdatecodes"
            url = codelist_api + query_params
            logger.debug(f"Inserting codelist entry for {cl_id} at {url} with payload {payload}")

            username = self.username
            password = self.password

            headers = {"Accept": "application/json"}

            # Make the GET request
            urllib3.disable_warnings()
            response = requests.post(url, headers=headers, auth=HTTPBasicAuth(username, password), json=payload,
                                     verify=False)

            # Success case
            if response.status_code == 200:
                execution_result = response.json()
                logger.debug("Codelist entry created successfully")

            else:
                logger.debug(response.text)
                logger.error(f"Failed to insert codelist entry. Status code: {response.status_code}")
                raise Exception(f"Failed to insert codelist entry. Status code: {response.status_code}")
        except requests.exceptions.RequestException as req_err:
            # Handles network, timeout, connection issues
            logger.error(f"Request error while inserting codelist entry {cl_id}: {req_err}")
            raise Exception(f"Request error while inserting codelist entry {cl_id}: {req_err}")
        except Exception as e:
            # Handles unexpected issues (JSON decode, etc.)
            logger.error(f"Unexpected error while inserting codelist entry for {cl_id}: {e}")
            raise Exception(f"Unexpected error while inserting codelist entry for {cl_id}: {e}")
        #finally:
        #    logger.debug(f"Finished execution of creating codelist entry for {cl_id}. URL: {url}")
        return execution_result

    def initialize_b2bi_properties(self, env, mode):
        self.url = f"{os.getenv(f"{env}_B2B_URL")}"
        self.username = f"{os.getenv(f"{env}_B2B_USER")}"
        self.password = f"{os.getenv(f"{env}_B2B_PASSWORD")}"
        self.version_id = ""
        self.execution_mode = mode
        self.env = env


    def deploy_b2b_artifacts(self, b2bi_obj: B2BI, env_name: str, mode: str = "preview"):
        logger.info("Deploying B2BI artifacts...")
        self.initialize_b2bi_properties(env_name, mode)

        self.deploy_identify_consumer(b2bi_obj.identify_consumer)
        self.deploy_delivery_cd(b2bi_obj.delivery_cd)
        self.deploy_delivery_gen(b2bi_obj.delivery_gen)
        self.deploy_delivery_sftp(b2bi_obj.delivery_sftp)
        self.deploy_delivery_wsmq(b2bi_obj.delivery_wsmq)
        self.deploy_delivery_filesystem(b2bi_obj.delivery_filesystem)
        self.deploy_delivery_db(b2bi_obj.delivery_db)
        self.deploy_delivery_azurefilestrorage(b2bi_obj.delivery_azure_filestorage)
        self.deploy_collect_sftp(b2bi_obj.collect_sftp)
        self.deploy_delivery_email(b2bi_obj.delivery_email)

        logger.info("B2BI artifacts deployment completed.")

