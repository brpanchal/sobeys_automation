import os
import  json
import time
import requests
import urllib3
import base64
from dotenv import load_dotenv
from typing import Dict, Any, List
from .logger import logger
from .constants import *
from .formatted_report import render_table

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

def get_cd_artifacts(env, backup=False, node=None):
    logger.debug(f"Executing CD artifacts")
    _, result_1 = send_request("GET", os.getenv('CDWS_RULES_WATCHDIR'), env)
    _, result_2 = send_request("GET", os.getenv('CDWS_CDP_PROCESS_LIST'), env)

    ## get backup of existing CD artifacts before update if backup flag Trues
    if backup:
        logger.info(f"========== Started backup of CD artifacts for node {node} ==========")
        node_backup = f"{PARENT_DIR}/{CD_BACKUP_PATH}/{node}"
        os.makedirs(node_backup, exist_ok=True)
        #Store Rule and watchdir
        with open(os.path.join(node_backup, f"{node}_{CD_RULE_N_WATCHDIR_FILE}"), "w") as json_file:
            json.dump(result_1, json_file, indent=4)

        #Store CDP Process list meta data
        with open(os.path.join(node_backup, f"{node}_{CD_PROCESS_LIST_FILE}"), "w") as json_file:
            json.dump(result_2, json_file, indent=4)

        #Store CDP process data
        cdp_dir = f"{node_backup}/{node}_{CDP_BACKUP_PATH}"
        os.makedirs(cdp_dir, exist_ok=True)
        for item in result_2[0]['PROCESSFILES']:
            process_url = f'{os.getenv('CDWS_CDP_PROCESS')}?{PROCESS_FILE_NAME}={item['fileName']}'
            _, result_3 = send_request("GET", process_url, env)
            with open(os.path.join(cdp_dir, f"{item['fileName']}"), "w",  encoding="utf-8", newline="\n") as f:
                f.write(result_3[0]['processFile'])

        logger.info(f"========== Completed backup of CD artifacts for node {node} ==========")

    return result_1, result_2

def display_cd_artifacts(result, result_1, host_dict):
    wd_root = result['watchDirs']
    rl_root = result['rules']
    cdp_root = result_1[0]
    traverse_cert_tree(wd_root, host_dict)
    traverse_cert_tree(rl_root, host_dict)
    traverse_cert_tree(cdp_root, host_dict)

def get_payload(payload):
    try:
        node = payload.pop("node", None)
        hostname = payload.pop("hostname", None)
        os_type = payload.pop("os_type", None)

        return payload, {'node': node, 'hostname': hostname, 'os_type': os_type}
    except Exception as e:
        raise Exception(f"Unexpected exception during payload : {str(e)}")

def extract_cd_fields(node: Dict[str, Any], root_type=None, key:str=None) -> Dict[str, Any]:
    """
    Safely extract core certificate fields with defaults.
    """
    if root_type == ROOT_TYPE[0]:
        wd_dict = { col:node.get(col, "N/A") for col in WATCHDIR_COL }
        wd_dict.update({"label": key})
        return wd_dict

    elif root_type == ROOT_TYPE[1]:
        rule_dict = {col: node.get(col, "N/A") for col in RULE_LIST_COL}
        rule_dict.update({"label": key})
        return rule_dict

    elif root_type == ROOT_TYPE[2]:
        return {
            PROCESS_LIST_COL: node.get(PROCESS_LIST_COL, "N/A")
        }

    return {}

def traverse_cert_tree(root, host_dict = None):
    """
    Depth-first traversal collecting certificate info across all levels.
    Each row includes the 'path' showing the lineage (Parent → Child → Subchild).
    """
    rows = []
    root_type = None
    root_data=[]
    for rtype in ROOT_TYPE:
        if root.get(rtype, None):
            root_type = rtype
            root_data = root.get(rtype)

    if root_type:
        if isinstance(root_data, dict):
            for key, rdict in root_data.items():
                rows.append(extract_cd_fields(rdict, root_type, key))
            logger.info("\n"+format_tree_report(host_dict.get("node", "N/A"), rows, root_type))
        elif isinstance(root_data, list):
            for row in root_data:
                rows.append(extract_cd_fields(row, root_type))
            logger.info("\n"+format_tree_report(host_dict.get("node", "N/A"), rows, root_type))
    return rows


def format_tree_report(node_name: str, rows: List[Dict[str, Any]], root_type):
    """
    Render a column hierarchy report in ASCII table format.

    """
    # Prepare rows normalized to strings and handle missing keys gracefully
    normalized = []
    table=None

    # Convert to user-friendly strings
    def fmt(v):
        if v is None or v == "":
            return "-"
        if isinstance(v, bool):
            return "True" if v else "False"
        return str(v)

    title = f"{root_type} Artifacts for node: {node_name}"

    if root_type == ROOT_TYPE[2]:
        for r in rows:
            normalized.append([str(r.get(PROCESS_LIST_COL) or "-")])
        # Headers
        headers = [PROCESS_LIST_COL]
        table = render_table(
            headers=headers,
            rows=normalized,
            title=title,
            style="unicode",
            padding=1,
            max_widths=80
        )

    elif root_type == ROOT_TYPE[1]:
        for r in rows:
            data = []
            for val in RULE_LIST_COL:
                data.append(str(r.get(val)) if r.get(val) == False else str(r.get(val) or "-"))
            normalized.append(data)
        # Headers
        headers = RULE_LIST_COL

        table = render_table(
            headers=headers,
            rows=normalized,
            title=title,
            style="unicode",
            padding=1,
            max_widths=[34, 12, 62, 42, 22]  # tweak as needed
        )

    elif root_type == ROOT_TYPE[0]:
        for r in rows:
            data = []
            for val in ['label']+WATCHDIR_COL:
                data.append(fmt(r.get(val)))
            normalized.append(data)
        # Headers
        headers = ["Path/Label"]+WATCHDIR_COL

        # Use unicode; if your environment garbles borders, you can switch to style="ascii".
        table = render_table(
            headers=headers,
            rows=normalized,
            title=title,
            style="unicode",  # or "ascii" for +---+ borders
            padding=1,
            max_widths=[28, 40, 48, 24]  # adjust per your screen/log width
        )

    return table

def ensure_sign_out(env):
    try:
        sign_out(env)
    except Exception as e1:
        logger.debug(f"Unexpected exception found during execution: {str(e1)}")

def count_dicts(data):
    if isinstance(data, dict):
        return 1
    if isinstance(data, list):
        return sum(count_dicts(item) for item in data)
    return 0

def formatted_timedata(start_time, end_time):
    formatted_start_time = time.strftime("%H:%M:%S", time.localtime(start_time))
    formatted_end_time = time.strftime("%H:%M:%S", time.localtime(end_time))
    return formatted_start_time, formatted_end_time

def display_summary(summary_data, total_time, env, node_count, overall_time):
    success_count = failed_count = 0
    table = render_table(
        headers=SUMMARY_COL,
        rows=summary_data,
        title=SUMMARY_TITLE+f":- Date:{datetime.now().strftime("%d-%m-%Y")}, Environment:{env}, Total Nodes:{node_count}",
        style="unicode",
        padding=1,
        max_widths=[28, 40, 48, 80, 22, 48]
    )
    for data in summary_data:
        if data[2]=='Success':
            success_count += 1
        elif data[2]=='Failed':
            failed_count += 1

    logger.info("\n" + table)
    logger.info(f"Success: {success_count}    Failed: {failed_count}")
    logger.info(overall_time)
    logger.info(f"Total process duration: {total_time:.2f} seconds")

def run_cd_rewind_service(node_list_json, args):
    try:
        host_dict={}
        dict_count = count_dicts(node_list_json)
        counter = total_time = 0
        overall_start_time = time.time()
        summary_data = []
        for node_list in node_list_json:
            for node in node_list:
                if isinstance(node, dict) and node.get('node'):
                    counter += 1
                    node_data=[]
                    start_time = time.time()
                    try:
                        logger.info(f"========== Processing started for node [{counter}/{dict_count}]: {node['node']} =============")
                        payload, host_dict = get_payload(node)
                        ensure_signed_on(args.env, host_dict)
                        if args.execution_mode == 'preview':
                            result_1, result_2 = get_cd_artifacts(args.env)
                            logger.info(f"========== Found existing CD artifacts details for node {host_dict['node']} ==========")
                            display_cd_artifacts(result_1, result_2, host_dict)
                        else:
                            logger.debug(f"Updating CD artifacts for node: {host_dict['node']}")
                            get_cd_artifacts(args.env, True, host_dict['node'])
                        logger.info(f"========== Processing completed for node {host_dict['node']} =============")
                        node_data.extend([counter, host_dict['node'], "Success", 'Node process succeeded.'])
                    except Exception as e:
                        logger.error(f"========== Processing failed for CD artifacts due to {e} ==========")
                        node_data.extend([counter, host_dict.get('node') or node.get('node'), 'Failed', f'Node process failed due to {e}'])
                    finally:
                        ensure_sign_out(args.env)

                    end_time = time.time()
                    total_elapsed_time = end_time - start_time
                    total_time += total_elapsed_time
                    stime, etime = formatted_timedata(start_time, end_time)
                    node_data.extend([f"{total_elapsed_time:.2f}s", f"{stime} - {etime}"])
                    summary_data.append(node_data)
        overall_end_time = time.time()
        ostime, oetime = formatted_timedata(overall_start_time, overall_end_time)
        overall_time = f"Start Time: {ostime}   End Time:{oetime}"
        display_summary(summary_data, total_time, args.env, dict_count, overall_time)

    except Exception as e:
        raise Exception(f"Unexpected exception found during execution: {str(e)}")