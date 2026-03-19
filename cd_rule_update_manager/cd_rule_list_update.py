import os
import  json
import logging
import time
import requests
import urllib3
import base64
import argparse
from dotenv import load_dotenv

# Configure the logger
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename="app.log",
    filemode="a"
)

# Add console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
console_handler.setFormatter(console_formatter)

# Get the root logger and add the console handler
logger = logging.getLogger()
logger.addHandler(console_handler)


""" Description about variables
    Create a logger instance
    Loads variables from .env into environment
    Initialize token, csrf, cookies, session if not exist
"""
logger = logging.getLogger(__name__)
load_dotenv()
token = None
cookies = None
csrf = None
session = requests.Session()

def read_rule_list_json():
    with open(os.getenv("RULE_LIST_FILE"), 'r') as f:
        return json.load(f)

def sign_on(endpoint, env, host_dict):
    global token, cookies, csrf, session
    sign_on_status = False
    json_res = {}
    base_url = f"{os.getenv(f"{env}_CDWS_URL")}:{os.getenv(f"CDWS_PORT")}"
    url = f"{base_url}{endpoint}"
    if "windows" in host_dict['os_type']:
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

    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Authorization': base64_encoded_credential,
               'X-XSRF-TOKEN': "Y2hlY2tpdA=="
               }

    payload = {'ipAddress': host_dict['hostname'],
               'port': port,
               'protocol': "TLS1.2",
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
    return {
        'Accept': 'application/json',
        'CONTENT-TYPE': 'application/json',
        'Authorization': token,
        'Cookie': cookies,
        'X-XSRF-TOKEN': csrf
    }

def send_request(method, endpoint, env, payload=None):
    status = False
    res = None
    base_url = f"{os.getenv(f"{env}_CDWS_URL")}:{os.getenv(f"CDWS_PORT")}"
    if method == "GET":
        url=f"{base_url}/{endpoint}?limit=500"
    else:
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

def get_rules(env):
    logger.debug(f"Executing CD get_rules")
    return send_request("GET", os.getenv('CDWS_FA_RULES'), env)

def is_rule_exist(name, env):
    status, get_rules_res = get_rules(env)

    if status:
        if get_rules_res:
            logger.debug("Found total records %s", get_rules_res['totalRecords'])
            matching_rule = [
                rule for rule in get_rules_res.get("rules", [])
                if rule.get("name") == name
            ]
            if matching_rule:
                message = (f"File Agent Rule is already exists with match criteria: {name}\n"
                           f"Showing current Configuration.")
                logger.debug(message)
                logger.debug(f"Existing rule : {matching_rule}")
                return True, matching_rule[0]
        return False, None
    else:
        msg = f"Skipping to find File Agent rule due to CD get_rules Failed!"
        logger.debug(msg)
        raise RuntimeError(msg)

def update_rule(payload, env):
    payload = {k: (str(v).lower() if isinstance(v, bool) else v) for k, v in payload.items()}
    return send_request("PUT", os.getenv("CDWS_FA_RULES"), env, payload)

def apply_changes(env):
    logger.debug(f"Executing CD apply_changes")
    return send_request("PUT", os.getenv('CDWS_FA_APPLY'), env)

def input_parser():
    parser = argparse.ArgumentParser(
        description="Deploy interfaces on a given environment"
    )

    # Add arguments
    parser.add_argument(
        "--env", required=True,
        help="Choose target environment (e.g., dev, qa, prod)."
    )

    parser.add_argument(
        "--execution-mode", required=True,
        choices=["preview", "execute"],
        default="preview",
        help="Choose 'preview' to simulate changes or 'execute' to apply the changes.)"
    )
    args = parser.parse_args()
    return args

def get_payload(payload):
    node = payload.pop("node", None)
    hostname = payload.pop("hostname", None)
    os_type = payload.pop("os_type", None)
    return payload, {'node': node, 'hostname': hostname, 'os_type': os_type}

def main():
    args = input_parser()
    try:
        rule_list_json = read_rule_list_json()
        for payload in rule_list_json:
            payload, host_dict = get_payload(payload)
            ensure_signed_on(args.env, host_dict)
            rule_exist, exist_rule_json = is_rule_exist(payload.get("name"), args.env)
            if rule_exist:
                exist_rule_json['fileNameKeyvalues'] = payload['fileNameKeyvalues']
                if args.execution_mode == "preview":
                    logger.debug(f"Final Rule_Payload to preview: {exist_rule_json}")
                else:
                    logger.debug(f"Final Rule_Payload to update: {exist_rule_json}")
                    update_rule(exist_rule_json, args.env)
                    apply_changes(args.env)
            else:
                logger.debug("No Rule_Payload found to update")
            sign_out(args.env)
    except Exception as e:
        sign_out(args.env)
        logger.error(f"Unexpected exception found during {args.execution_mode} : {str(e)}")
        raise Exception(f"Unexpected exception found during {args.execution_mode} : {str(e)}")


if __name__ == '__main__':
    main()