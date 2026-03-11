import os
import  json
import time
import requests
import urllib3
import base64
from dotenv import load_dotenv
from streamlit import success

from .logger import logger, timestamp
from .constants import *
import  re

load_dotenv()
token = None
cookies = None
csrf = None
report_list = []
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
        logger.info(f"Started backup of initparams details for node {node}")
        node_backup = f"{NODE_INIT_BACKUP_PATH}{timestamp}"
        os.makedirs(PARENT_DIR+node_backup, exist_ok=True)
        with open(os.path.join(PARENT_DIR, node_backup, f"{node}_INITPARAMS.json"), "w") as json_file:
            json.dump(result, json_file, indent=4)
        logger.info(f"Completed backup of initparams details for node {node}")
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

def prepare_initparams_data(host_dict, data, flag):
    global report_list
    if isinstance(data, list):
        initparamsdata = data[0]['initParmsData']

        PATTERN_FILEAGENT = re.compile(
            r'(?i)(?P<prefix>\bfileagent\.enable\s*=\s*)(?P<val>[YN])\b'
        )

        PATTERN_CDFA = re.compile(
            r'(?i)(?P<prefix>\bcdfa\.enable\s*=\s*)(?P<val>[yn])\b'
        )

        if "windows" in host_dict['os_type'].lower():
            pattern = PATTERN_FILEAGENT
            updated_value = flag.upper()
            display_key = 'fileagent.enable'
        else:
            pattern = PATTERN_CDFA
            updated_value = flag.lower()
            display_key = 'cd.file.agent:cdfa.enable'

        m = re.search(pattern, initparamsdata)
        current_value = None
        if m:
            current_value =m.group('val')
        final_result =  pattern.sub(lambda m: m.group("prefix") + updated_value, initparamsdata)
        data[0]['initParmsData'] = final_result
        #logger.info(f"Updated data to be pushed: {display_key}:{updated_value} & Payload:{data}")
        action = 'Skipped' if current_value == updated_value else "Updated"
    else:
        #logger.info(f"Actual init params data: {json.dumps(data, indent=4)}")
        if "windows" in host_dict['os_type'].lower():
            current_value = data['File Agent']['fileagent.enable']
            data['File Agent']['fileagent.enable'] = flag.upper()
            display_key = 'fileagent.enable'
            updated_value = flag.upper()
        else:
            current_value = data['cd.file.agent']['cdfa.enable']
            data['cd.file.agent']['cdfa.enable'] = flag.lower()
            display_key = 'cd.file.agent:cdfa.enable'
            updated_value = flag.lower()
        #logger.info(f"Updated data to be pushed: {display_key}:{flag} & Payload:{json.dumps(data, indent=4)}")
        action = 'Skip' if current_value == updated_value else "Update"

    report_list.append([host_dict['node'], host_dict['os_type'], display_key, current_value, updated_value, action])
    return data, action

def format_tree_report(rows) -> str:
    """
    Render a initparms hierarchy report in ASCII table format.
    """
    # Prepare rows normalized to strings and handle missing keys gracefully

    # Headers
    headers = ["Node", "OS Type", "FileAgent Key", "Current FileAgent Status", "New FileAgent Status", "Action/Status"]

    # Compute column widths: max of header and content per column
    col_widths = [
        max(len(headers[0]), *(len(row[0]) for row in rows)) if rows else len(headers[0]),
        max(len(headers[1]), *(len(row[1]) for row in rows)) if rows else len(headers[1]),
        max(len(headers[2]), *(len(row[2]) for row in rows)) if rows else len(headers[2]),
        max(len(headers[3]), *(len(row[3]) for row in rows)) if rows else len(headers[3]),
        max(len(headers[4]), *(len(row[4]) for row in rows)) if rows else len(headers[4]),
        max(len(headers[5]), *(len(row[5]) for row in rows)) if rows else len(headers[5])
    ]

    # Helper to build a row with padding
    def build_row(cols, widths, sep="│"):
        cells = [
            f" {str(col).ljust(width)} " for col, width in zip(cols, widths)
        ]
        return sep + sep.join(cells) + sep

    # Helper to build horizontal rules
    def build_rule(widths, style="top"):
        # style: "top", "mid", "bottom"
        if style == "top":
            left, mid, right, junction = "┌", "┬", "┐", "─"
        elif style == "mid":
            left, mid, right, junction = "├", "┼", "┤", "─"
        else:
            left, mid, right, junction = "└", "┴", "┘", "─"

        segments = [junction * (w + 2) for w in widths]  # +2 for spaces added around cells
        return left + mid.join(segments) + right

    # Title banner (kept from your original style, width expanded to table width)
    table_total_width = sum(w + 2 for w in col_widths) + (len(col_widths) + 1)  # cells + separators
    title_line = f"│   Initparms fileAgent details for all nodes   │"

    # Adjust title box width to match table width aesthetically (minimum to fit)
    # Ensure the decorative box matches or exceeds the table width
    deco_inner_width = max(len(title_line) - 2, table_total_width - 2)
    deco_top = "┌" + "─" * deco_inner_width + "┐"
    deco_bottom = "└" + "─" * deco_inner_width + "┘"
    # Re-center the title within the decorative box
    title_text = f"   Initparms fileAgent details for all nodes   "
    padding = deco_inner_width - len(title_text)
    if padding >= 0:
        left_pad = padding // 2
        right_pad = padding - left_pad
        title_line = "│" + (" " * left_pad) + title_text + (" " * right_pad) + "│"
    else:
        # Fallback if node_name is extremely long; truncate
        trimmed = title_text[:deco_inner_width]
        title_line = "│" + trimmed + "│"

    lines = [
        "",
        deco_top,
        title_line,
        deco_bottom,
        build_rule(col_widths, style="top"),
        build_row(headers, col_widths),
        build_rule(col_widths, style="mid"),
    ]

    # Data rows
    if rows:
        for row in rows:
            lines.append(build_row(row, col_widths))
    else:
        # No data case
        lines.append(build_row(("— No data —", "", ""), [col_widths[0], col_widths[1], col_widths[2]]))

    lines.append(build_rule(col_widths, style="bottom"))
    lines.append("")

    return "\n".join(lines)

def prerequisite_to_process_node(node):
    fileagent = node.get("fileagent.enable", "")
    hostname = node.get("hostname", "")
    os_type = node.get("os_type", "")
    if not(os_type and hostname):
        raise Exception(f"node_list not configured properly. either hostname or os_type not found or invalid values for node:{node.get('node')}.")

    if not fileagent:
        raise Exception(f"No fileagent config found for node:{node.get('node')}.")

    if fileagent.lower() not in ['y', 'n']:
        raise Exception(f"fileagent value configured wrongly for node:{node.get('node')}.")

def run_initparms_service(node_list_json, args):
    global report_list
    total_start_time = time.time()
    success = failed = 0
    try:
        for node_list in node_list_json:
            for node in node_list:
                try:
                    logger.info(f"========== Processing started for node {node['node']} =============")
                    prerequisite_to_process_node(node)
                    payload, host_dict = get_payload(node)
                    ensure_signed_on(args.env, host_dict)

                    if args.execution_mode == 'preview':
                        result = get_initparam_details(args.env, True)
                        prepare_initparams_data(host_dict, result, payload['fileagent.enable'])
                    else:
                        logger.debug(f"Updating CD Initparams for node: {host_dict['node']}")
                        result = get_initparam_details(args.env, False, True, host_dict['node'])
                        modifiedinit, action = prepare_initparams_data(host_dict, result, payload['fileagent.enable'])
                        if action == 'Updated':
                            status, res = update_initparam_details(modifiedinit, args.env)
                            if status:
                                logger.info(f"CD Initparams file agent has been successfully updated for node: {host_dict['node']} and received response: {res}")
                            else:
                                logger.info(f"CD Initparams file agent has been failed for node: {host_dict['node']} and received response: {res}")
                        else:
                            logger.info("Process is skipped due to same status found.")
                    logger.info(f"========== Processing completed for node {host_dict['node']} =============")
                    success += 1
                except Exception as e:
                    logger.error(f"========== Processing failed for CD Initparams due to {e} ==========")
                    failed += 1
                finally:
                    ensure_sign_out(args.env)
        total_end_time = time.time()
        logger.info(format_tree_report(report_list))
        logger.info(f"Success: {success}  Failed: {failed}")
        logger.info(f"Total execution duration: {total_end_time - total_start_time:.2f} seconds")
        return failed
    except Exception as e:
        raise Exception(f"Unexpected exception found during execution: {str(e)}")