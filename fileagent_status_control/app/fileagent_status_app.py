import os
import json
import time
import requests
import urllib3
import base64
from dotenv import load_dotenv
from .logger import logger, timestamp
from .constants import *
import re
from enum import StrEnum
import html
from pathlib import Path

load_dotenv()
token = None
cookies = None
csrf = None
report_list = []
session = requests.Session()

class Systems(StrEnum):
    WINDOWS = "windows"
    UNIX = "unix"
    AIX = "aix"
    LINUX = "linux"

class FileAgentStatusEnum(StrEnum):
    PREVIEW = "preview"
    SKIP = "Skip"
    SKIPPED = "Skipped"
    UPDATE = "Update"
    UPDATED = "Updated"


def sign_on(endpoint, env, host_dict) -> Systems:
    """
        This is to sign on CD server with given env and node details
        :param endpoint: endpoint uri
        :param env: environment name
        :param host_dict: host details
        :return: status and response
    """
    global token, cookies, csrf, session
    sign_on_status = False
    base_url = f"{os.getenv(f"{env}_CDWS_URL")}:{os.getenv(f"CDWS_PORT")}"
    url = f"{base_url}{endpoint}"

    #If os_type windows then prepare auth data with cred.., port
    if Systems.WINDOWS in host_dict[OS_TYPE].lower():
        credentials = f"{os.getenv(f"{env}_CD_WIN_USER")}:{os.getenv(f"{env}_CD_WIN_PASSWORD")}"
        encoded_bytes = base64.b64encode(credentials.encode("utf-8"))
        encoded_str = encoded_bytes.decode("utf-8")
        base64_encoded_credential = f"Basic {encoded_str}"
        port = int(f"{os.getenv(f"{env}_CD_WIN_PORT")}")
    else:
        #Else prepare auth data with unix cred, port
        credentials = f"{os.getenv(f"{env}_CD_UNIX_USER")}:{os.getenv(f"{env}_CD_UNIX_PASSWORD")}"
        encoded_bytes = base64.b64encode(credentials.encode("utf-8"))
        encoded_str = encoded_bytes.decode("utf-8")
        base64_encoded_credential = f"Basic {encoded_str}"
        port = int(f"{os.getenv(f"{env}_CD_UNIX_PORT")}")

    #header with auth and token details
    headers = {'Accept': os.getenv("CONTENT_TYPE"),
               'Content-Type': os.getenv("CONTENT_TYPE"),
               'Authorization': base64_encoded_credential,
               'X-XSRF-TOKEN': os.getenv("XSRF_TOKEN")
               }

    #required payload
    payload = {'ipAddress': host_dict[HOSTNAME],
               'port': port,
               'protocol': os.getenv("PROTOCOL"),
               }

    try:
        #Initiate API call
        logger.debug(f"Executing CD sign_on, URL:{url}")
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = session.post(url=url, json=payload, headers=headers, verify=False)
        response.raise_for_status()

        #Response in json
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
    """
        Ensures signed on to CD server with env and node data
    """
    time.sleep(1)
    global token
    if not token:
        sign_on(os.getenv("CDWS_SIGNON"), env, host_dict)


def sign_out(env):
    """
        This is to sign out from CD server where logged in for node
        :param env:environment like dev, qa, prod
    """
    global token
    logger.debug(f"Executing CD sign_out")
    payload = {'userAccessToken': token}
    send_request("DELETE", os.getenv('CDWS_LOGOUT'), env, payload)
    token = None
    return


def get_headers():
    """
        Get header with defined parameter like auth and token
    """
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
    """
        Send a request to the CD endpoint with API details
        :param method: HTTP method
        :param endpoint: CD endpoint
        :param env: CD environment
        :param payload: CD payload
        :return: HTTP response
    """
    base_url = f"{os.getenv(f"{env}_CDWS_URL")}:{os.getenv(f"CDWS_PORT")}"
    url = f"{base_url}{endpoint}"
    headers = get_headers()

    try:
        #API call
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
    """
        This is GET Api call to get the initparms data from CD server based on env, json_type along with backup.
        If backup required for any node initparms data then backup parameter should be True
    """
    logger.debug(f"Executing CD get_initparams")
    endpoint = f"{os.getenv('CDWS_INITPARAM')}"
    if json_type:
        endpoint = f"{endpoint}?formatOutput=y"
    _, result = send_request("GET", endpoint, env)
    time.sleep(2)

    ## get backup of existing initparms data before update if backup flag Trues
    if backup:
        logger.info(f"Started backup of initparams details for node {node}")
        node_backup = f"{NODE_INIT_BACKUP_PATH}{timestamp}"
        os.makedirs(PARENT_DIR + node_backup, exist_ok=True)
        file_dir = os.path.join(PARENT_DIR, node_backup, f"{node}_INITPARAMS.json")
        file_path = Path(file_dir)
        absolute_path = file_path.resolve()
        with open(file_dir, "w") as json_file:
            json.dump(result, json_file, indent=4)
        logger.info(f"Completed backup of initparams details for node {node} on path:{absolute_path}")
    return result


def update_initparam_details(payload, env):
    """
        This is to decoded payload data with utf-8 and send the formatted payload to API server
    """
    raw = payload[0][INITPARMSDATA]

    #decoded the payload data with safe unicode
    #decoded_text = payload.encode("utf-8").decode("unicode_escape")
    if isinstance(raw, str) and len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            # If not valid JSON, just fall back to the original text
            pass

    # 3) Unescape HTML entities like &lt;None&gt;
    decoded_text = html.unescape(raw)

    # 4) Build the outgoing payload.
    #    If the receiving API expects plain text, send as-is.
    #    If it expects JSON, let json library escape as needed.
    outgoing_payload = {INITPARMSDATA: decoded_text}

    return send_request("PUT", os.getenv("CDWS_INITPARAM"), env, outgoing_payload)


def get_payload(payload):
    """
        This is to filter out node data separately long with payload data
    """
    #Separating node data like node name. hostname, os_type
    node = payload.pop(NODE, None)
    hostname = payload.pop(HOSTNAME, None)
    os_type = payload.pop(OS_TYPE, None)

    return payload, {NODE: node, HOSTNAME: hostname, OS_TYPE: os_type}


def ensure_sign_out(env):
    """
        This is to sign out from cd server as per env logged in
    """
    try:
        sign_out(env)
    except Exception as e1:
        logger.debug(f"Unexpected exception found during execution: {str(e1)}")


def prepare_initparams_data(host_dict, data, status, mode) -> Systems:
    """
        Prepare init parameter data for a node by computing the current FileAgent status,
        deriving the desired value from `flag` based on OS type, and determining the action
        (SKIP/UPDATE) via `perform_action`. Also appends a row to the global `report_list`
        for reporting.
        Parameters
        ----------
        host_dict : dict
            Normalized host metadata for the node. Must contain:
            - 'node' (str): Node identifier
            - 'hostname' (str)
            - 'os_type' (str): Used to select which parameter to read/write
        data : list|dict
            Current initparams payload. Either:
            - list: with the first element containing a key 'initParmsData' (str) for raw text
            - dict: JSON-like structure containing FILEAGENT_PREFIX/FILEAGENT_KEY for Unix or
                    keys from CDFA_KEY (split by ':') for Windows
        status : str|None
            Desired fileagent status value to set. Will be normalized based on OS:
            - Windows: upper ('Y'/'N')
            - Unix: lower ('y'/'n')
            If None, treated as "not mentioned".
        mode : str
            Execution mode, typically 'preview' or 'execute'. Passed to `perform_action`
            for action selection.
    """
    global report_list
    if isinstance(data, list):
        initparamsdata = data[0][INITPARMSDATA]

        # Regex for unix and windows fileagent status search
        PATTERN_FILEAGENT = re.compile(FILEAGENT_REGEX)
        PATTERN_CDFA = re.compile(CDFA_REGEX)

        # If os_type is windows then preparing pattern, requested flag and get status of fileagent.enable parameter
        if Systems.WINDOWS in host_dict[OS_TYPE].lower():
            pattern = PATTERN_FILEAGENT
            display_key = FILEAGENT_KEY
            new_status_value = status.upper() if isinstance(status, str) else None
        else:
            # If os_type is unix or anyother then preparing pattern, requested flag and get status of cdfa.enable parameter
            pattern = PATTERN_CDFA
            display_key = CDFA_KEY
            new_status_value = status.lower() if isinstance(status, str) else None

        # Searching the defined fileagent parameter based on os_type
        m = re.search(pattern, initparamsdata)
        current_status_value = None
        if m:
            current_status_value = m.group('val')
        final_result = pattern.sub(lambda m: m.group("prefix") + new_status_value if new_status_value else "", initparamsdata)
        data[0][INITPARMSDATA] = final_result
    else:
        # As preview mode If os_type is windows then preparing data with pattern, requested flag and get status of fileagent.enable parameter
        if Systems.WINDOWS in host_dict[OS_TYPE].lower():
            current_status_value = data[FILEAGENT_PREFIX][FILEAGENT_KEY]
            display_key = FILEAGENT_KEY
            status_value = status.upper() if isinstance(status, str) else None
            new_status_value = status_value
            data[FILEAGENT_PREFIX][FILEAGENT_KEY] = status_value
        else:
            # If os_type is unix or any other then preparing data with pattern, requested flag and get status of cdfa.enable parameter
            fa_flag = CDFA_KEY.split(":")
            current_status_value = data[fa_flag[0]][fa_flag[1]]
            display_key = CDFA_KEY
            status_value = status.lower() if isinstance(status, str) else None
            new_status_value = status_value
            data[fa_flag[0]][fa_flag[1]] = status_value

    # Based on current and request fileagent.enable value it determines the action to be performed.
    action, newval = perform_action(current_status_value, new_status_value, mode)

    #Appending row data of node in global report_list to display in table format
    report_list.append(
        ["", host_dict[NODE], host_dict[HOSTNAME], host_dict[OS_TYPE], display_key, current_status_value, newval,
         action])
    return data, action


def perform_action(current, newval, mode) -> FileAgentStatusEnum:
    """
    Based on execution mode, returning action as skip, update and message
        If no fileagent.enable not defined in node_list.json then returns 'Skip', 'Not Mentioned'
        If fileagent.enable defined with invalid value then it returns as 'Skip','Invalid value'
        If current fileagent status and new status are same then returns as 'Skip', latest fileagent status value
        Otherwise return Update, Latest fileagent status value
    """
    if newval is None:
        #`fileagent.enable` is NOT provided in `node_list.json`returns Skip, message = 'Not Mentioned'
        return FileAgentStatusEnum.SKIP if mode == FileAgentStatusEnum.PREVIEW else FileAgentStatusEnum.SKIPPED, STATUS_MSG[0]
    elif newval.lower() not in STATUS_LIST:
        #`fileagent.enable` is provided but invalid (not 'y'/'n' case-insensitive)
        # returns Skip, message = 'Invalid value'
        return FileAgentStatusEnum.SKIP if mode == FileAgentStatusEnum.PREVIEW else FileAgentStatusEnum.SKIPPED, STATUS_MSG[1]
    elif current == newval:
        #current status equals desired status (case-insensitive match)
        # returns Skip, requested value
        return FileAgentStatusEnum.SKIP if mode == FileAgentStatusEnum.PREVIEW else FileAgentStatusEnum.SKIPPED, newval
    else:
        #Otherwise (a change is required)
        # returns Update, requested value
        return FileAgentStatusEnum.UPDATE if mode == FileAgentStatusEnum.PREVIEW else FileAgentStatusEnum.UPDATED, newval


def format_tree_report(rows) -> str:
    """
        Render a initparms hierarchy report in ASCII table format.
        It takes the input as raws means which having multiple row to display in table format with header
        Header:
                ["Sr. No.", "Node", "Hostname", "OS Type", "FileAgent Key", "Current FileAgent Status", "New FileAgent Status", "Action/Status"]
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
            row[0] = str(index + 1)
            lines.append(build_row(row, col_widths))
    else:
        # No data case
        lines.append(build_row(("", "", "", "", "— No data —", "", "", ""),
                               [col_widths[0], col_widths[1], col_widths[2], col_widths[3], col_widths[4],
                                col_widths[5], col_widths[6], col_widths[7]]))

    lines.append(build_rule(col_widths, style="bottom"))
    lines.append("")

    return "\n".join(lines)


def prerequisite_to_process_node(node):
    """
        Validate the prerequisite node based on availability
    """
    hostname = node.get(HOSTNAME, "")
    os_type = node.get(OS_TYPE, "")
    node_name = node.get(NODE, "")
    if not (os_type and hostname and node_name):
        raise Exception(
            f"node_list not configured properly. either hostname, node name or os_type not found or invalid values for node:{node.get(NODE)}.")

    values = [s.value for s in Systems]
    if os_type not in values:
        raise Exception(
            f"os type('{os_type}') is not valid as per system list {values} for node:{node.get(NODE)}.")

def generate_report(mode, success, failed, skipped, updated, skip, update, total_time) -> FileAgentStatusEnum:
    """
        Generate a consolidated execution report for FileAgent status processing.

        This function prints a summary of the operation based on whether the script
        was run in preview mode or execution mode. It logs aggregated counts of node
        outcomes (successes, failures, skips, updates) as well as the total duration
        of the operation. The report is also enriched by logging a formatted tree
        structure maintained globally in `report_list`.

        Parameters
        ----------
        mode : str
            Execution mode of the script. Expected values:
            - 'preview' : No changes applied, only actions evaluated.
            - any other value (e.g., 'execute') : Actual update operations performed.

        success : int
            Number of nodes processed without raising any exception.

        failed : int
            Number of nodes for which processing failed due to an exception.

        skipped : int
            (Execution mode only)
            Nodes where no update was applied because:
            - The current state already matches the desired state, or
            - The configuration is incorrect or incomplete.

        updated : int
            (Execution mode only)
            Number of nodes where an update operation was successfully applied.

        skip : int
            (Preview mode only)
            Count of nodes that would be skipped if execution were performed.

        update : int
            (Preview mode only)
            Count of nodes that would be updated if execution were performed.

        total_time : float
            Total wall-clock time for the entire operation, in seconds.
    """
    global report_list
    # Log hierarchical table format report generated during processing
    logger.info(format_tree_report(report_list))
    # Display mode-based summary
    if mode == FileAgentStatusEnum.PREVIEW:
        logger.info(
            f"Success: {success}  Failed: {failed}  Skip:{skip}   Update:{update}")
    else:
        logger.info(f"Success: {success}  Failed: {failed}  Skipped:{skipped}   Updated:{updated}")
    logger.info(f"Total execution duration: {total_time:.2f} seconds")
    logger.info("ℹ️ CD File Agent status naming conventions: y/n for Unix ; Y/N for Windows")


def fileagent_status_service(node_list, args) -> FileAgentStatusEnum:
    """
        Orchestrates preview/update of CD FileAgent status across a list of nodes.

        This function iterates over nested node lists, performs prerequisite checks,
        prepares payload and host metadata, signs in to the target environment,
        and then either:
          - PREVIEW mode: evaluates actions (skip/update) without applying changes, or
          - EXECUTION mode: fetches current initparams, computes the required action (skipped/updated) ,
            and initparams data if needed.

        For each node, it maintains counters to summarize the run and generates a final
        report at the end.

        Parameters
        ----------
        node_list : list[dict]
            Nested list of node json data
        args : argparse.Namespace or similar
            Object containing:
              - env (str): Target environment identifier (e.g., "dev", "qa", "prod")
              - execution_mode (str): Either 'preview' or 'execute'.
    """
    total_start_time = time.time()

    # Aggregate counters for reporting
    success = failed = skipped = updated = 0  # execution-mode counters
    skip = update = 0  # preview-mode counters

    try:
        # Iterate through outer lists, then individual nodes
        for node in node_list:
            try:
                # Validate node is ready for processing
                prerequisite_to_process_node(node)
                logger.info(f"========== Processing started for node {node[NODE]} =============")
                # Construct required payload and normalized host metadata for downstream calls
                payload, host_dict = get_payload(node)
                # Establish a session in the target environment
                ensure_signed_on(args.env, host_dict)

                if args.execution_mode == FileAgentStatusEnum.PREVIEW:
                    # PREVIEW: Only compute the action; do NOT perform updates
                    result = get_initparam_details(args.env, True)
                    _, action = prepare_initparams_data(host_dict, result, payload.get(FILEAGENT_KEY, None),
                                                        args.execution_mode)
                    # Count preview decision outcomes # e.g., "Skip" "Update"
                    if action == FileAgentStatusEnum.SKIP:
                        skip += 1
                    else:
                        update += 1
                else:
                    # EXECUTION: Fetch current state for the specific node, compute action, and apply if needed
                    logger.debug(f"Updating CD FileAgent status for node: {host_dict[NODE]}")
                    result = get_initparam_details(args.env, False, True, host_dict[NODE])
                    init_result, action = prepare_initparams_data(host_dict, result,
                                                                  payload.get(FILEAGENT_KEY, None),
                                                                  args.execution_mode)
                    # Perform update only when action denotes "Skipped/Updated"
                    if action == FileAgentStatusEnum.UPDATED:
                        status, res = update_initparam_details(init_result, args.env)
                        if status:
                            updated += 1
                            logger.info(
                                f"CD file agent status has been successfully updated for node: {host_dict[NODE]} and received response: {res}")
                        else:
                            logger.info(
                                f"CD file agent status has been failed for node: {host_dict[NODE]} and received response: {res}")
                    else:
                        # No change necessary or config incorrect; record as skipped
                        skipped += 1
                        logger.info(
                            "Current status matches the requested status or incorrect configured; skipping the update.")
                logger.info(f"========== Processing completed for node {host_dict[NODE]} =============")
                success += 1
            except Exception as e:
                # Node-level exceptions are logged; processing continues for subsequent nodes
                logger.error(f"========== Processing failed for CD FileAgent due to {e} ==========")
                failed += 1
            finally:
                # Always ensure we sign out per node to avoid session leakage
                ensure_sign_out(args.env)
        total_end_time = time.time()
        # Generate a consolidated report after all nodes are processed
        generate_report(args.execution_mode, success, failed, skipped, updated, skip, update,
                        total_end_time - total_start_time)
        return failed
    except Exception as e:
        raise Exception(f"⛔ Unexpected exception found during execution: {str(e)}")
