import os
import json
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

def prepare_initparams_data(host_dict, data, flag, mode):
    global report_list
    if isinstance(data, list):
        initparamsdata = data[0]['initParmsData']

        PATTERN_FILEAGENT = re.compile(FILEAGENT_REGEX)
        PATTERN_CDFA = re.compile(CDFA_REGEX)

        if SYSTEMS[0] in host_dict['os_type'].lower():
            pattern = PATTERN_FILEAGENT
            display_key = FILEAGENT_KEY
            updated_value = flag.upper() if isinstance(flag, str) else None
        else:
            pattern = PATTERN_CDFA
            display_key = CDFA_KEY
            updated_value = flag.lower() if isinstance(flag, str) else None

        m = re.search(pattern, initparamsdata)
        current_value = None
        if m:
            current_value =m.group('val')
        final_result =  pattern.sub(lambda m: m.group("prefix") + updated_value if updated_value else "", initparamsdata)
        data[0]['initParmsData'] = final_result
    else:
        if SYSTEMS[0] in host_dict['os_type'].lower():
            current_value = data['File Agent']['fileagent.enable']
            display_key = FILEAGENT_KEY
            flag_value = flag.upper() if isinstance(flag, str) else None
            updated_value = flag_value
            data['File Agent']['fileagent.enable'] = flag_value
        else:
            current_value = data['cd.file.agent']['cdfa.enable']
            display_key = CDFA_KEY
            flag_value = flag.lower() if isinstance(flag, str) else None
            updated_value = flag_value
            data['cd.file.agent']['cdfa.enable'] = flag_value

    action, newval = perform_action(current_value, updated_value, mode)

    report_list.append(["1", host_dict['node'], host_dict['hostname'], host_dict['os_type'], display_key, current_value, newval, action])
    return data, action

def perform_action(current, newval, mode):
    if newval is None:
        return PREVIEW_ACTION[0] if mode == "preview" else PREVIEW_ACTION[1], STATUS_MSG[0]
    elif newval.lower() not in ['y', 'n']:
        return PREVIEW_ACTION[0] if mode == "preview" else PREVIEW_ACTION[1], STATUS_MSG[1]
    elif current == newval:
        return PREVIEW_ACTION[0] if mode == "preview" else PREVIEW_ACTION[1], newval
    else:
        return EXECUTE_ACTION[0] if mode == "preview" else EXECUTE_ACTION[1], newval

def format_tree_report(rows) -> str:
    """
    Render a initparms hierarchy report in ASCII table format.
    """

    # Headers
    headers = TABLE_HEADER

    # Compute column widths: max of header and content per column
    col_widths = [
        max(len(headers[0]), *(len(row[0]) for row in rows)) if rows else len(headers[0]),
        max(len(headers[1]), *(len(row[1]) for row in rows)) if rows else len(headers[1]),
        max(len(headers[2]), *(len(row[2]) for row in rows)) if rows else len(headers[2]),
        max(len(headers[3]), *(len(row[3]) for row in rows)) if rows else len(headers[3]),
        max(len(headers[4]), *(len(row[4]) for row in rows)) if rows else len(headers[4]),
        max(len(headers[5]), *(len(row[5]) for row in rows)) if rows else len(headers[5]),
        max(len(headers[6]), *(len(row[6]) for row in rows)) if rows else len(headers[6]),
        max(len(headers[7]), *(len(row[7]) for row in rows)) if rows else len(headers[7])
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
    title_line = f"│   {TITLE}   │"

    # Adjust title box width to match table width aesthetically (minimum to fit)
    # Ensure the decorative box matches or exceeds the table width
    deco_inner_width = max(len(title_line) - 2, table_total_width - 2)
    deco_top = "┌" + "─" * deco_inner_width + "┐"
    deco_bottom = "└" + "─" * deco_inner_width + "┘"
    # Re-center the title within the decorative box
    title_text = f"   {TITLE}   "
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
        for index, row in enumerate(rows):
            row[0] =  str(index+1)
            lines.append(build_row(row, col_widths))
    else:
        # No data case
        lines.append(build_row(("", "", "", "", "— No data —", "", "", ""), [col_widths[0], col_widths[1], col_widths[2], col_widths[3], col_widths[4], col_widths[5], col_widths[6], col_widths[7]]))

    lines.append(build_rule(col_widths, style="bottom"))
    lines.append("")

    return "\n".join(lines)

def prerequisite_to_process_node(node):
    hostname = node.get("hostname", "")
    os_type = node.get("os_type", "")
    if not(os_type and hostname):
        raise Exception(f"node_list not configured properly. either hostname or os_type not found or invalid values for node:{node.get('node')}.")

def generate_report(mode, success, failed, skipped, updated, skip, update, total_time):
    global report_list
    logger.info(format_tree_report(report_list))
    if mode == 'preview':
        logger.info(
            f"Success: {success}  Failed: {failed}  Skip:{skip}   Update:{update}")
    else:
        logger.info(f"Success: {success}  Failed: {failed}  Skipped:{skipped}   Updated:{updated}")
    logger.info(f"Total execution duration: {total_time:.2f} seconds")
    logger.info("ℹ️ CD File Agent status naming conventions: y/n for Unix ; Y/N for Windows")

def fileagent_status_service(node_list_json, args):
    total_start_time = time.time()
    success = failed = skipped = updated = skip = update = 0
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
                        _, action = prepare_initparams_data(host_dict, result, payload.get('fileagent.enable', None), args.execution_mode)
                        if action == PREVIEW_ACTION[0]:
                            skip+=1
                        else:
                            update+=1
                    else:
                        logger.debug(f"Updating CD FileAgent status for node: {host_dict['node']}")
                        result = get_initparam_details(args.env, False, True, host_dict['node'])
                        modifiedinit, action = prepare_initparams_data(host_dict, result, payload.get('fileagent.enable', None), args.execution_mode)
                        if action == EXECUTE_ACTION[1]:
                            status, res = update_initparam_details(modifiedinit, args.env)
                            if status:
                                updated += 1
                                logger.info(f"CD file agent status has been successfully updated for node: {host_dict['node']} and received response: {res}")
                            else:
                                logger.info(f"CD file agent status has been failed for node: {host_dict['node']} and received response: {res}")
                        else:
                            skipped+=1
                            logger.info("Current status matches the requested status or incorrect configured; skipping the update.")
                    logger.info(f"========== Processing completed for node {host_dict['node']} =============")
                    success += 1
                except Exception as e:
                    logger.error(f"========== Processing failed for CD FileAgent due to {e} ==========")
                    failed += 1
                finally:
                    ensure_sign_out(args.env)
        total_end_time = time.time()
        generate_report(args.execution_mode, success, failed, skipped, updated, skip, update,
                        total_end_time - total_start_time)
        return failed
    except Exception as e:
        raise Exception(f"Unexpected exception found during execution: {str(e)}")