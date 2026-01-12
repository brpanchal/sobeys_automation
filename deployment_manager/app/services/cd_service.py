import base64
import json
import logging
import os
import time
import  re

import requests
import urllib3
from dotenv import load_dotenv

from app.models.connect_direct import ConnectDirect
from app.constants import PATTERN, RULE_KEYS, MATCH_MAP

load_dotenv()  # Loads variables from .env into environment
logger = logging.getLogger(__name__)


class CDServices:
    def __init__(self):
        self.base_url = None
        self.session = requests.Session()
        self.token = None
        self.csrf = None
        self.cookies = None
        self.base64_encoded_credential = None
        self.hostname = None
        self.port = None

    def __get_headers(self):
        return {
            'Accept': 'application/json',
            'CONTENT-TYPE': 'application/json',
            'Authorization': self.token,
            'Cookie': self.cookies,
            'X-XSRF-TOKEN': self.csrf
        }

    def __send_request(self, method, endpoint, payload=None):
        status = False
        res = None

        self.__ensure_signed_on()
        url = f"{self.base_url}/{endpoint}"
        headers = self.__get_headers()

        try:
            response = self.session.request(method, url, json=payload, headers=headers, verify=False)
            response.raise_for_status()
            res = response.json()
            status = True
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTPError exception during {method} {endpoint} : {str(e)}")
            errormsg = json.loads(e.response.text)['errorMessage']
            if bool(re.match(PATTERN, errormsg, re.IGNORECASE)):
                logger.warning(errormsg)
                return False, errormsg
            elif e.response is not None:
                raise Exception(f"HTTPError exception Text: {e.response.text}")
            raise Exception(f"HTTPError exception during {method} {endpoint} : {str(e)}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request exception during {method} {endpoint} : {str(e)}")
            if e.response is not None:
                raise Exception(f"Request exception Text: {e.response.text}")
            raise Exception(f"Request exception during {method} {endpoint} : {str(e)}")
        except Exception as e:
            raise Exception(f"Unexpected exception found during {method} {endpoint} : {str(e)}")

        logger.debug(f"{method} {endpoint} Finished!!")
        return status, res

    def __sign_on(self, endpoint):
        sign_on_status = False
        json_res = {}

        url = f"{self.base_url}/{endpoint}"

        headers = {'Accept': 'application/json',
                   'Content-Type': 'application/json',
                   'Authorization': self.base64_encoded_credential,
                   'X-XSRF-TOKEN': "Y2hlY2tpdA=="
                   }

        payload = {'ipAddress': self.hostname,
                   'port': self.port,
                   'protocol': "TLS1.2",
                   }

        try:
            logger.debug(f"Executing CD sign_on, URL:{url}")
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            response = self.session.post(url=url, json=payload, headers=headers, verify=False)
            response.raise_for_status()

            json_res = response.json()

            if response.status_code == 200:
                sign_on_status = True
                self.token = response.headers['authorization']
                self.csrf = response.headers['_csrf']
                self.cookies = response.headers['set-cookie']
                msg = f"CDWS sign_on Successful!! Response: {response.text}"
                logger.debug(msg)
            else:
                logger.debug(f"CD Sign-on Failed!! status_code: {response.status_code}")
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTPError exception during sign_on : {str(e)}")
            if e.response is not None:
                raise Exception(f"HTTPError exception!! Text: {e.response.text}")
            raise Exception(f"HTTPError exception during sign_on : {str(e)}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request exception during sign_on : {str(e)}")
            if e.response is not None:
                raise Exception(f"Request exception!! Text: {e.response.text}")
            raise Exception(f"Request exception during sign_on : {str(e)}")
        except Exception as e:
            raise Exception(f"Unexpected exception found during sign_on : {str(e)}")

        logger.debug("CD sign_on Finished!!")
        return sign_on_status, json_res

    def __sign_out(self):
        logger.debug(f"Executing CD sign_out")
        payload = {'userAccessToken': self.token}
        return self.__send_request("DELETE", os.getenv('CDWS_LOGOUT'), payload)

    def __ensure_signed_on(self):
        time.sleep(1)
        if not self.token:
            self.__sign_on(os.getenv('CDWS_SIGNON'))

    def __get_process_library(self):
        logger.debug(f"Executing CD get_process_library")
        return self.__send_request("GET", os.getenv('CDWS_CDP_LIST'))

    def __get_watch_directories(self):
        logger.debug(f"Executing CD get_watch_directories")
        return self.__send_request("GET", os.getenv('CDWS_WATCHDIR'))

    def __get_rules(self):
        logger.debug(f"Executing CD get_rules")
        return self.__send_request("GET", os.getenv('CDWS_FA_RULES')+"?limit=1000")

    def __create_cdp_file(self, payload):
        logger.debug(f"Executing CD create_cdp_file")
        logger.debug(f"payload: {payload}")
        return self.__send_request("POST", os.getenv('CDWS_CDP'), payload)

    def __create_watch_directory(self, payload):
        logger.debug(f"Executing CD create_watch_directory")
        # lower case the True/False value from payload
        payload = {k: (str(v).lower() if isinstance(v, bool) else v) for k, v in payload.items()}
        logger.debug(f"payload: {payload}")
        return self.__send_request("POST", os.getenv('CDWS_WATCHDIR'), payload)

    def __create_rule(self, payload):
        logger.debug(f"Executing CD create_rule")
        # lower case the True/False value from payload
        payload = {k: (str(v).lower() if isinstance(v, bool) else v) for k, v in payload.items()}
        logger.debug(f"payload: {payload}")
        return self.__send_request("POST", os.getenv('CDWS_FA_RULES'), payload)

    def __update_rule(self, payload):
        logger.debug(f"Executing CD update_rule to update")
        # lower case the True/False value from payload
        payload = {k: (str(v).lower() if isinstance(v, bool) else v) for k, v in payload.items()}
        logger.debug(f"payload: {payload}")
        return self.__send_request("PUT", os.getenv('CDWS_FA_RULES'), payload)

    def __apply_changes(self):
        logger.debug(f"Executing CD apply_changes")
        return self.__send_request("PUT", os.getenv('CDWS_FA_APPLY'))

    ################################## VALIDATE CDP Process ###################################
    def is_cdp_exist(self, cdp_name):
        status, get_cdp_list_res = self.__get_process_library()
        if status:
            get_cdp_list_res = get_cdp_list_res[0]
            # If no cdp file present in cdp library list.
            if get_cdp_list_res and 'PROCESSFILES' not in get_cdp_list_res:
                return False
            elif get_cdp_list_res:
                matching_cdp = next((entry for entry in get_cdp_list_res.get("PROCESSFILES", [])
                                     if entry.get("fileName") == cdp_name),
                                    None  # default if no match is found
                                    )
                if matching_cdp:
                    message = f"CDP Process '{cdp_name}'.cdp is already exists. Showing current configuration."
                    logger.debug(message)
                    logger.debug(f"Existing cdp file : {matching_cdp}")
                    return True
            return False
        else:
            msg = f"Skipping to create CD Process due to get CD get_process_library Failed!"
            logger.debug(msg)
            raise RuntimeError(msg)

    ################################ VALIDATE WATCH DIRECTORY #################################
    def is_watch_dir_exist(self, watch_dir_name):
        status, watch_dir_json = self.__get_watch_directories()

        # Handling if no records are present in watch directory
        if status:
            if watch_dir_json and watch_dir_json["totalRecords"] == 0:
                return False
            else:
                matching_watch_dir = next((entry for entry in watch_dir_json.get("watchDirList", [])
                        if entry.get("watchedDir") == watch_dir_name),
                        None  # default if no match is found
                        )
                if matching_watch_dir:
                    msg = f"Watch Directory {watch_dir_name} already exists."
                    logger.debug(msg)
                    logger.debug(f"Existing watch directory : {matching_watch_dir}")
                    return True
            return False
        else:
            msg = f"Skipping to create watch directory due to CD get_watch_directories Failed!"
            logger.debug(msg)
            raise RuntimeError(msg)

    def is_rule_exist(self, latest_rule):
        def _display_rule_list(rule_1, rule_2):
            logger.info("Rule to be deployed: %s", rule_1)
            logger.info("Existing matched rule from server: %s", rule_2)

        # Raise exception when rule name key not found in provided rule.
        latest_rule = {
            k: MATCH_MAP.get(v.lower(), v) if isinstance(v, str) else v
            for k, v in latest_rule.items()
        }
        latest_name = latest_rule.get("name")
        if latest_name is None:
            raise Exception("Rule name not provided or missing in the supplied CD rule list.")

        # Retrieving rules list from CD server with all fields
        status, get_rules_res = self.__get_rules()

        if not status:
            msg = "Skipping creation of File Agent rule: CD get_rules failed."
            logger.info(msg)
            raise RuntimeError(msg)

        rules = (get_rules_res or {}).get("rules", [])
        if not rules:
            return False, 'INSERT'

        # Find first match by provided rule name in retrieved rule list
        matched_rule = next((r for r in rules if r.get("name") == latest_name), None)
        if matched_rule is None:
            logger.info(
                f"No matching rule found on server for name '{latest_name}'. "
                f"Rule will be inserted."
            )
            return False, 'INSERT'

        # Compare only relevant keys (RULE_KEYS should exclude ignored ones)
        differences = {}
        # Compare relevant fields only
        for key in RULE_KEYS:
            if matched_rule.get(key) != latest_rule.get(key):
                differences[key] = {
                    "server": matched_rule.get(key),
                    "provided": latest_rule.get(key)
                }

        # If any field differs, log the mismatch and the details
        if differences:
            logger.info(
                    f"Mismatch detected between provided rule and server rule for name '{latest_name}'. "
                    f"Rule needs to be updated."
            )

            # Log each differing field
            for field, diff in differences.items():
                logger.info(
                    f"Field '{field}' differs: Provided={diff['provided']} | CD Server={diff['server']}"
                )
            return False, 'UPDATE'

        logger.info(
            f"Rule '{latest_name}' already exists on the server with identical configuration. Skipping Insert/update."
        )
        _display_rule_list(latest_rule, matched_rule)
        return True, 'SKIP'

    def initialize_cd_properties(self, env, os_type, hostname, credential_type):
        """
        Function will generate base64 encoded string from username and password based on Host OS type (windows, Linux).
        :return:
        """
        if hostname is None:
            raise RuntimeError(f"Hostname cannot be None.")
        if os_type is None:
            raise RuntimeError(f"OS cannot be None.")
        if credential_type is None:
            raise RuntimeError(f"Credential cannot be None.")

        self.hostname = hostname
        credentials = ""
        self.base_url = f"{os.getenv(f"{env}_CDWS_URL")}:{os.getenv(f"CDWS_PORT")}"
        if "windows" in os_type.lower():
            if credential_type == "default":
                credentials = f"{os.getenv(f"{env}_CD_WIN_USER")}:{os.getenv(f"{env}_CD_WIN_PASSWORD")}"
            #TODO: Exception case
            encoded_bytes = base64.b64encode(credentials.encode("utf-8"))
            encoded_str = encoded_bytes.decode("utf-8")
            self.base64_encoded_credential = f"Basic {encoded_str}"
            self.port = int(f"{os.getenv(f"{env}_CD_WIN_PORT")}")
        else:
            if credential_type == "default":
                credentials = f"{os.getenv(f"{env}_CD_UNIX_USER")}:{os.getenv(f"{env}_CD_UNIX_PASSWORD")}"
            encoded_bytes = base64.b64encode(credentials.encode("utf-8"))
            encoded_str = encoded_bytes.decode("utf-8")
            self.base64_encoded_credential = f"Basic {encoded_str}"
            self.port = int(f"{os.getenv(f"{env}_CD_UNIX_PORT")}")

        logger.debug(f"CDWS base_url: {self.base_url}")
        logger.debug(f"Connect:Direct Properties:")
        logger.debug(f"os_type: {os_type}")
        logger.debug(f"Host: {self.hostname}")
        logger.debug(f"Port: {self.port}")
        logger.debug(f"Credential: {credential_type}")

    def deploy_watch_dir(self, watch_dir_content, mode="preview"):
        logger.info(f"Watch directory starting")
        try:
            watch_dir_payload = json.loads(watch_dir_content)
            watch_dir_name = watch_dir_payload['watchedDir']
            watch_dir_exist = self.is_watch_dir_exist(watch_dir_name)
            if not watch_dir_exist:
                if mode == "preview":
                    logger.debug(f"Watch_Dir_Payload to be deployed: {watch_dir_payload}")
                else:
                    self.__create_watch_directory(watch_dir_payload)
                    self.__apply_changes()
        except Exception as e:
            raise RuntimeError(f"Failed to deploy watch_dir, RuntimeError: {e}")
        logger.info(f"Watch directory completed")

    def __validate_cdp_name_per_os(self, os_type, cdp_payload):
        if "windows" in os_type.lower():
            pattern = re.compile(r'(\b[\w.-]+)\s+PROCESS\b', re.IGNORECASE)
            matches = pattern.findall(cdp_payload['processFileData'])
            if len(matches[0]) > 8:
                raise Exception(
                    f"CDP Process name '{matches[0]}' is too long. Can be 8 characters maximum for windows system.")

    def deploy_cdp(self, cdp_name, cdp_content, os_type,  mode="preview"):
        logger.info(f"CDP starting")
        try:
            cdp_payload = json.loads(cdp_content)
            self.__validate_cdp_name_per_os(os_type, cdp_payload)
            cdp_exist = self.is_cdp_exist(cdp_name)
            if not cdp_exist:
                if mode == "preview":
                    logger.debug(f"CDP_Payload: {cdp_payload}")
                else:
                    self.__create_cdp_file(cdp_payload)
        except Exception as e:
            raise RuntimeError(f"Failed to deploy CDP {cdp_name}, RuntimeError: {e}")
        logger.info(f"CDP completed")

    def deploy_rule(self, rule_content, mode="preview"):
        logger.info(f"Rule starting")
        try:
            data = json.loads(rule_content)
            rule_exist, entry_type = self.is_rule_exist(data)
            if not rule_exist:
                if mode == "preview":
                    logger.debug(f"Rule_Payload: {data}")
                elif entry_type=='UPDATE':
                    self.__update_rule(data)
                    self.__apply_changes()
                    logger.info(f"Rule updated successfully")
                else:
                    self.__create_rule(data)
                    self.__apply_changes()
                    logger.info(f"Rule inserted successfully")
        except Exception as e:
            raise RuntimeError(f"Failed to deploy Rule, RuntimeError: {e}")
        logger.info(f"Rule completed")

    def deploy_cd_artifacts(self, cd_obj:ConnectDirect, env, mode="preview"):
        logger.info("Deploying CD artifacts...")
        self.initialize_cd_properties(env.upper(), cd_obj.os_type, cd_obj.hostname, cd_obj.credentials)

        # Sign in to Connect:Direct
        status, sign_on_json = self.__sign_on(os.getenv('CDWS_SIGNON'))
        if not status:
            raise RuntimeError(f"Failed to sign on to Connect:Direct : {sign_on_json}.")

        self.deploy_cdp(cd_obj.cdp_name, cd_obj.cdp, cd_obj.os_type, mode)
        self.deploy_watch_dir(cd_obj.watch_dir, mode)
        self.deploy_rule(cd_obj.rule, mode)

        # Sign out from the Connect:Direct
        self.__sign_out()
        logger.info("CD artifacts deployment completed.")