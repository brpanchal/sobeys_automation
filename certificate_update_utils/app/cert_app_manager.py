import os
import  json
import time
import requests
import urllib3
import base64
from dotenv import load_dotenv
from datetime import datetime
from typing import Dict, Any, List, Iterable
from .logger import logger
from .constants import *

## TODO: create rollback with pem file
""" Description about variables
    Loads variables from .env into environment
    Initialize token, csrf, cookies, session if not exist
"""
load_dotenv()
token = None
cookies = None
csrf = None
session = requests.Session()
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

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

def get_certificate(env, backup=False, node=None):
    logger.debug(f"Executing CD get_certificate")
    _, result = send_request("GET", os.getenv('CDWS_CERT'), env)

    ## get backup of existing certificate before update if backup flag Trues
    if backup:
        node_backup = f"{NODE_CERT_BACKUP_PATH}{timestamp}"
        os.makedirs(PARENT_DIR+node_backup, exist_ok=True)
        with open(os.path.join(PARENT_DIR, node_backup, f"{node}_CERT.json"), "w") as json_file:
            json.dump(result[0][0], json_file, indent=4)
    return result

def update_certificate(payload, env):
    return send_request("PUT", os.getenv("CDWS_CERT"), env, payload)

def print_cert_validity(result, host_dict):
    root_cert = result[0]
    rows = traverse_cert_tree(root_cert)
    logger.info(format_tree_report(host_dict.get("node", "N/A"), rows))

def check_certificate_validity(result, host_dict):
    root_cert = result[0]
    rows = traverse_cert_tree(root_cert)
    all_valid = []

    for row in rows:
        if 'severity:OK' in row.get("validTo"):
            all_valid.append(True)
        else:
            all_valid.append(False)

    logger.info(format_tree_report(host_dict.get("node", "N/A"), rows))
    if not all(all_valid):
        logger.info("Still one or more certificates are expired or near to expire or invalid.")
    return True

def get_payload(payload, certificates):
    node = payload.pop("node", None)
    hostname = payload.pop("hostname", None)
    os_type = payload.pop("os_type", None)
    payload["importMode"]= "add_or_replace"
    payload["syncNodes"]= ""
    if  SYSTEMS[0] in os_type.lower():
        payload['certificateData'] =  certificates['windows_cert']
    elif SYSTEMS[1] in os_type.lower():
        payload['certificateData'] =  certificates['aix_cert']
    else:
        payload['certificateData'] =  certificates['unix_cert']

    return payload, {'node': node, 'hostname': hostname, 'os_type': os_type}


def iter_children(node: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    """
    Return an iterable of children/subchildren for the given node.
    Adjust keys here to match your actual schema.
    """
    # Common patterns: children list, subCertificates list, or nested parent/child dicts
    # If your model uses different keys, add them here.
    for key in POSSIBLE_CHILD_KEYS:
        if key in node and isinstance(node[key], list):
            yield from node[key]

    # If there's a single nested certificate chain (e.g., parentCertificate is a dict)
    if isinstance(node.get("parentCertificate"), dict):
        yield node["parentCertificate"]

def extract_cert_fields(node: Dict[str, Any]) -> Dict[str, Any]:
    """
    Safely extract core certificate fields with defaults.
    """
    return {
        "label": node.get("certificateLabel", "N/A"),
        "validFrom": node.get("validFrom", "N/A"),
        "validTo": node.get("validTo", "N/A"),
        "commonName": node.get("commonName", "N/A"),
    }

def traverse_single_root(root, path):
    rows = []
    current = extract_cert_fields(root)
    current_path = path + [current["label"]]

    def _format_date(sdate, only_date=False):
        today = datetime.today().date()
        tokens = sdate.split()
        cleaned = ' '.join(tokens[:4] + [tokens[-1]])
        dt = datetime.strptime(cleaned, '%a %b %d %H:%M:%S %Y').date()
        if only_date:
            return dt.strftime('%Y-%m-%d')
        # Days to expiry
        days_left = (dt - today).days
        if days_left < EXPIRED_SEV_DAYS:
            severity = "EXPIRED"
        elif days_left <= CRITICAL_SEV_DAYS:
            severity = "CRITICAL"
        elif days_left <= WARNING_SEV_DAYS:
            severity = "WARNING"
        else:
            severity = "OK"
        return f"{dt.strftime('%Y-%m-%d')} | Days left:{days_left} | severity:{severity}"

    rows.append({
        "path": " > ".join([p for p in current_path if p and p != "N/A"]),
        "label": current["label"],
        "validFrom": _format_date(current["validFrom"], True),
        "validTo": _format_date(current["validTo"]),
        "commonName": current["commonName"],
    })

    for child in iter_children(root):
        rows.extend(traverse_single_root(child, current_path))
    return rows

def traverse_cert_tree(root: Dict[str, Any], path: List[str] = None) -> List[Dict[str, Any]]:
    """
    Depth-first traversal collecting certificate info across all levels.
    Each row includes the 'path' showing the lineage (Parent → Child → Subchild).
    """
    if path is None:
        path = []

    rows_1 = []
    if isinstance(root, list):
        for one_root in root:
            rows_1.extend(traverse_single_root(one_root, path))
    return rows_1


def format_tree_report(node_name: str, rows: List[Dict[str, Any]]) -> str:
    """
    Render a certificate hierarchy report in ASCII table format.

    Columns:
      - Path/Label
      - Valid From
      - Valid To
      - Days Left
      - Severity
      - comonName
    """
    # Prepare rows normalized to strings and handle missing keys gracefully
    normalized = []
    for r in rows:
        path_or_label = str(r.get("path") or r.get("label") or "-")
        valid_from = str(r.get("validFrom") or "-")
        valid_to = str(r.get("validTo") or "-")
        parts = valid_to.split('|')
        valid_to = str(parts[0] or "-")
        days_left = str(parts[1].split(":")[1] or "-")
        severity = str(parts[2].split(":")[1] or "-")
        common_name = str(node_name + ":" + r.get("commonName"))
        normalized.append((path_or_label, valid_from, valid_to, days_left, severity, common_name))

    # Headers
    headers = ("Path/Label", "Valid From", "Valid To", "Days Left", "Severity", "Common Name")

    # Compute column widths: max of header and content per column
    col_widths = [
        max(len(headers[0]), *(len(row[0]) for row in normalized)) if normalized else len(headers[0]),
        max(len(headers[1]), *(len(row[1]) for row in normalized)) if normalized else len(headers[1]),
        max(len(headers[2]), *(len(row[2]) for row in normalized)) if normalized else len(headers[2]),
        max(len(headers[3]), *(len(row[3]) for row in normalized)) if normalized else len(headers[3]),
        max(len(headers[4]), *(len(row[4]) for row in normalized)) if normalized else len(headers[4]),
        max(len(headers[5]), *(len(row[5]) for row in normalized)) if normalized else len(headers[5]),
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
    title_line = f"│   Certificate Hierarchy for node: {node_name:<24}│"

    # Adjust title box width to match table width aesthetically (minimum to fit)
    # Ensure the decorative box matches or exceeds the table width
    deco_inner_width = max(len(title_line) - 2, table_total_width - 2)
    deco_top = "┌" + "─" * deco_inner_width + "┐"
    deco_bottom = "└" + "─" * deco_inner_width + "┘"
    # Re-center the title within the decorative box
    title_text = f"   Certificate Hierarchy for node: {node_name}"
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
    if normalized:
        for row in normalized:
            lines.append(build_row(row, col_widths))
    else:
        # No data case
        lines.append(build_row(("— No certificates —", "", ""), [col_widths[0], col_widths[1], col_widths[2]]))

    lines.append(build_rule(col_widths, style="bottom"))
    lines.append("")

    return "\n".join(lines)


def ensure_sign_out(env):
    try:
        sign_out(env)
    except Exception as e1:
        logger.debug(f"Unexpected exception found during execution: {str(e1)}")


def run_cert_service(node_list_json, certificates, args):
    try:
        for node_list in node_list_json:
            for node in node_list:
                try:
                    logger.info(f"========== Processing started for node {node['node']} =============")
                    payload, host_dict = get_payload(node, certificates)
                    ensure_signed_on(args.env, host_dict)
                    if args.execution_mode == 'preview':
                        result = get_certificate(args.env)
                        logger.info(f"========== Found existing certificate details for node {host_dict['node']} ==========")
                        print_cert_validity(result, host_dict)
                    else:
                        logger.debug(f"Updating certificate for node: {host_dict['node']}")
                        get_certificate(args.env, True, host_dict['node'])
                        status, _ = update_certificate(payload, args.env)
                        res = get_certificate(args.env)
                        check_certificate_validity(res, host_dict)

                        if status:
                            logger.info(f"The key certificate has been successfully updated for node: {host_dict['node']}")
                        else:
                            logger.info(f"The key certificate has been failed for node: {host_dict['node']}")
                    logger.info(f"========== Processing completed for node {host_dict['node']} =============")
                except Exception as e:
                    logger.error(f"========== Processing failed for certificate due to {e} ==========")
                finally:
                    ensure_sign_out(args.env)
    except Exception as e:
        raise Exception(f"Unexpected exception found during execution: {str(e)}")