import os
import  json
import time
import requests
import urllib3
import base64
from dotenv import load_dotenv
from .logger import logger, timestamp
from .constants import *
import  re

load_dotenv()
token = None
cookies = None
csrf = None
session = requests.Session()

def sign_on(endpoint, env, host_dict):
    global token, cookies, csrf, session
    sign_on_status = False
    base_url = f"{os.getenv(f"{env}_CDWS_URL")}:{os.getenv(f"CDWS_PORT")}"
    url = f"{base_url}{endpoint}"
    if SYSTEMS[0] in host_dict['os_type'].lower():
        credentials = f"{os.getenv(f"{env}_CD_WIN_USER")}:{os.getenv(f"{env}_CD_WIN_PASSWORD")}"
        encoded_bytes = base64.b64encode(credentials.encode("utf-8"))
        encoded_str = encoded_bytes.decode("utf-8")
        base64_encoded_credential = f"Basic {encoded_str}"
        port = int(f"{os.getenv(f"{env}_CD_WIN_PORT")}")
    else:
        credentials = f"{os.getenv(f"{env}_CD_UNIX_USER")}:{os.getenv(f"{env}_CD_UNIX_PASSWORD")}"
        encoded_bytes = base64.b64encode(credentials.encode("utf-8"))
        encoded_str = encoded_bytes.decode("utf-8")
        base64_encoded_credential = f"Basic {encoded_str}"
        port = int(f"{os.getenv(f"{env}_CD_UNIX_PORT")}")

    headers = {'Accept': os.getenv("CONTENT_TYPE"),
               'Content-Type': os.getenv("CONTENT_TYPE"),
               'Authorization': base64_encoded_credential,
               'X-XSRF-TOKEN': os.getenv("XSRF_TOKEN")
               }

    payload = {'ipAddress': host_dict['hostname'],
               'port': port,
               'protocol': os.getenv("PROTOCOL"),
               }

    try:
        logger.debug(f"Executing CD sign_on, URL:{url}")
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = session.post(url=url, json=payload, headers=headers, verify=False)
        response.raise_for_status()

        json_res = response.json()

        if response.status_code == 200:
            sign_on_status = True
            token = response.headers['authorization']
            csrf = response.headers['_csrf']
            cookies = response.headers['set-cookie']
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

def ensure_signed_on(env, host_dict):
    time.sleep(1)
    global token
    if not token:
        sign_on(os.getenv("CDWS_SIGNON"), env, host_dict)

def sign_out(env):
    global token
    logger.debug(f"Executing CD sign_out")
    payload = {'userAccessToken': token}
    send_request("DELETE", os.getenv('CDWS_LOGOUT'), env, payload)
    token =None
    return

def get_headers():
    global token, cookies, csrf
    content_type = os.getenv("CONTENT_TYPE")
    return {
        'Accept': content_type,
        'CONTENT-TYPE': content_type,
        'Authorization': token,
        'Cookie': cookies,
        'X-XSRF-TOKEN': csrf
    }

def send_request(method, endpoint, env, payload=None):
    base_url = f"{os.getenv(f"{env}_CDWS_URL")}:{os.getenv(f"CDWS_PORT")}"
    url = f"{base_url}{endpoint}"
    headers = get_headers()

    try:
        response = session.request(method, url, json=payload, headers=headers, verify=False)
        response.raise_for_status()
        res = response.json()
        status = True
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTPError exception during {method} {endpoint} : {str(e)}")
        errormsg = json.loads(e.response.text)['errorMessage']
        logger.warning(errormsg)
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

def get_initparam_details(env, json_type=None, backup=False, node=None):
    logger.debug(f"Executing CD get_initparams")
    endpoint = f"{os.getenv('CDWS_INITPARAM')}"
    if json_type:
        endpoint = f"{endpoint}?formatOutput=y"
    _, result = send_request("GET", endpoint, env)
    time.sleep(2)

    ## get backup of existing certificate before update if backup flag Trues
    if backup:
        logger.debug(f"Started backup of initparams details for node {node}")
        node_backup = f"{NODE_INIT_BACKUP_PATH}{timestamp}"
        os.makedirs(PARENT_DIR+node_backup, exist_ok=True)
        with open(os.path.join(PARENT_DIR, node_backup, f"{node}_INITPARAMS.json"), "w") as json_file:
            json.dump(result, json_file, indent=4)
        logger.debug(f"Completed backup of initparams details for node {node}")
    return result

def update_initparam_details(payload, env):
    payload = payload[0]["initParmsData"]
    decoded_text = payload.encode("utf-8").decode("unicode_escape")
    return send_request("PUT", os.getenv("CDWS_INITPARAM"), env, {"initParmsData": decoded_text})

def get_payload(payload):
    node = payload.pop("node", None)
    hostname = payload.pop("hostname", None)
    os_type = payload.pop("os_type", None)

    return payload, {'node': node, 'hostname': hostname, 'os_type': os_type}

def ensure_sign_out(env):
    try:
        sign_out(env)
    except Exception as e1:
        logger.debug(f"Unexpected exception found during execution: {str(e1)}")

def prepare_initparams_data(os_type, data, flag):
    if isinstance(data, list):
        initparamsdata = data[0]['initParmsData']

        PATTERN_FILEAGENT = re.compile(
            r'(?i)(?P<prefix>\bfileagent\.enable\s*=\s*)(?P<val>[YN])\b'
        )

        PATTERN_CDFA = re.compile(
            r'(?i)(?P<prefix>\bcdfa\.enable\s*=\s*)(?P<val>[yn])\b'
        )

        if "windows" in os_type.lower():
            pattern = PATTERN_FILEAGENT
            final_value = flag.upper()
            display_key = 'fileagent.enable'
        else:
            pattern = PATTERN_CDFA
            final_value = flag.lower()
            display_key = 'cd.file.agent:cdfa.enable'

        final_result =  pattern.sub(lambda m: m.group("prefix") + final_value, initparamsdata)
        data[0]['initParmsData'] = final_result
        logger.info(f"Updated data to be pushed: {display_key}:{final_value} & Payload:{data}")
    else:
        #logger.info(f"Actual init params data: {json.dumps(data, indent=4)}")
        if "windows" in os_type.lower():
            data['File Agent']['fileagent.enable'] = flag.upper()
            display_key = 'fileagent.enable'
        else:
            data['cd.file.agent']['cdfa.enable'] = flag.lower()
            display_key = 'cd.file.agent:cdfa.enable'
        logger.info(f"Updated data to be pushed: {display_key}:{flag} & Payload:{json.dumps(data, indent=4)}")
    return data


def run_initparms_service(node_list_json, args):
    try:
        for node_list in node_list_json:
            for node in node_list:
                try:
                    logger.info(f"========== Processing started for node {node['node']} =============")
                    payload, host_dict = get_payload(node)
                    ensure_signed_on(args.env, host_dict)

                    if args.execution_mode == 'preview':
                        result = get_initparam_details(args.env, True)
                        logger.info(
                            f"========== Found existing CD Initparams details for node {host_dict['node']} ==========")
                        prepare_initparams_data(host_dict['os_type'], result, payload['fileagent.enable'])
                    else:
                        logger.debug(f"Updating CD Initparams for node: {host_dict['node']}")
                        result = get_initparam_details(args.env, False, True, host_dict['node'])
                        modifiedinit = prepare_initparams_data(host_dict['os_type'], result, payload['fileagent.enable'])
                        status, res = update_initparam_details(modifiedinit, args.env)
                        if status:
                            logger.info(f"The key CD Initparams has been successfully updated for node: {host_dict['node']} and received response: {res}")
                        else:
                            logger.info(f"The key CD Initparams has been failed for node: {host_dict['node']} and received response: {res}")
                    logger.info(f"========== Processing completed for node {host_dict['node']} =============")
                except Exception as e:
                    logger.error(f"========== Processing failed for CD Initparams due to {e} ==========")
                finally:
                    ensure_sign_out(args.env)
    except Exception as e:
        raise Exception(f"Unexpected exception found during execution: {str(e)}")