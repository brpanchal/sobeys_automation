import os
import  json
import logging
import time
import requests
import urllib3
import base64
import argparse
from dotenv import load_dotenv
from collections import defaultdict
from datetime import datetime

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
windows_cert = None
linux_cert = None
aix_cert = None
session = requests.Session()


def read_certificate_file(file_name, json_type=False):
    with open(os.getenv("PARENT_DIR")+os.getenv(file_name), 'r') as f:
        return json.load(f) if json_type else f.read()

def read_node_list_json():
    global windows_cert, linux_cert, aix_cert
    try:
        windows_cert = read_certificate_file("WINDOWS_CERTIFICATE")
        linux_cert = read_certificate_file("UNIX_CERTIFICATE")
        aix_cert = read_certificate_file("AIX_CERTIFICATE")
        node_list = read_certificate_file("NODE_LIST_FILE", True)
        buckets = defaultdict(list)
        for node in node_list:
            os_type = node.get("os_type", "").lower()
            if os_type in ("windows", "unix", "aix"):
                buckets[os_type].append(node)
    except Exception as e:
        raise Exception(f"Error reading certificate or nodes list file: {e}")

    return [buckets["windows"], buckets["unix"], buckets["aix"]]


def sign_on(endpoint, env, host_dict):
    global token, cookies, csrf, session
    sign_on_status = False
    json_res = {}
    base_url = f"{os.getenv(f"{env}_CDWS_URL")}:{os.getenv(f"CDWS_PORT")}"
    url = f"{base_url}{endpoint}"
    if "windows" in host_dict['os_type'].lower():
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

def get_certificate(env):
    logger.debug(f"Executing CD get_certificate")
    return send_request("GET", os.getenv('CDWS_CERT'), env)

def update_certificate(payload, env):
    return send_request("PUT", os.getenv("CDWS_CERT"), env, payload)

def check_certificate_validity(valid_to):
    formated_date = None
    validity_list = [valid_to[0][0]['validTo'], valid_to[0][0]['parentCertificate']['validTo']]
    for valid in validity_list:
        tokens = valid.split()
        # Remove the timezone token (2nd last) and keep: DOW Mon DD HH:MM:SS YEAR
        cleaned = ' '.join(tokens[:4] + [tokens[-1]])
        dt = datetime.strptime(cleaned, '%a %b %d %H:%M:%S %Y')
        formated_date = dt.date().strftime('%Y-%m-%d')
        # Compare to Jan 1, 2026
        if dt.date() > datetime(2026, 1, 16).date():
            continue
        else:
            return False, formated_date
    return True, formated_date

def input_parser():
    parser = argparse.ArgumentParser(
        description="Update Certificate for CD on a given environment"
    )

    # Add arguments
    parser.add_argument(
        "--env", required=True,
        help="Choose target environment (e.g., dev, qa, prod)."
    )
    args = parser.parse_args()
    return args

def get_payload(payload):
    global windows_cert, linux_cert, aix_cert
    node = payload.pop("node", None)
    hostname = payload.pop("hostname", None)
    os_type = payload.pop("os_type", None)
    payload["importMode"]= "add_or_replace"
    payload["syncNodes"]= ""
    if os_type.lower() == 'windows':
        payload['certificateData'] =  windows_cert
    elif os_type.lower() == 'linux':
        payload['certificateData'] =  linux_cert
    elif os_type.lower() == 'aix':
        payload['certificateData'] =  aix_cert
    else:
        payload['certificateData'] = ""

    return payload, {'node': node, 'hostname': hostname, 'os_type': os_type}

def main():
    args = input_parser()
    try:
        node_list_json = read_node_list_json()
        for index, node_list in enumerate(node_list_json):
            for node in node_list:
                payload, host_dict = get_payload(node)
                ensure_signed_on(args.env, host_dict)
                logger.debug(f"Updating certificate for node: {node}")
                #update_certificate(payload, args.env)
                _, result = get_certificate(args.env)
                status, new_date = check_certificate_validity(result)
                if status:
                    logger.debug(f"The key certificate has been successfully updated for node: {node} with validity: {new_date}")
                else:
                    logger.error(f"The key certificate has been failed for node: {node} with validity: {new_date}")
                sign_out(args.env)
    except Exception as e:
        sign_out(args.env)
        logger.error(f"Unexpected exception found during execution: {str(e)}")
        raise Exception(f"Unexpected exception found during execution: {str(e)}")


if __name__ == '__main__':
    main()