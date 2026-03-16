import os
import json
import argparse
import sys
from dotenv import load_dotenv
from app.logger import logger
from app.constants import *
from app.fileagent_status_app import fileagent_status_service

load_dotenv()

def read_file(file_name, path,  json_type=False):
    if file_name:
        with open(path+os.getenv(file_name), 'r') as f:
            return json.load(f) if json_type else f.read()
    return None

def read_node_list_json():
    try:
        node_list = read_file(NODE_LIST_FILE, PARENT_DIR, True)
        seq_list = []
        for node in node_list:
            seq_list.append([node])
        return seq_list
    except Exception as e:
        raise Exception(f"Error reading nodes list json file: {e}")

def input_parser():
    parser = argparse.ArgumentParser(
        description="Active Passive File Agent Status for node on CD on a given environment"
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

def main():
    args = input_parser()
    return_code = 0
    try:
        logger.info(f"========== CD Enable Disable file agent status process started: Env={args.env}, Execution mode={args.execution_mode} ==========")

        logger.info("========== Loading required configuration started =============")
        node_list_json = read_node_list_json()
        logger.info("========== Loading required configuration completed =============")
        status = fileagent_status_service(node_list_json, args)
        if status >0:
            return_code = 1
    except Exception as e:
        logger.error(f"Unexpected exception found during execution: {str(e)}")
        return_code = 1
        raise Exception(f"Unexpected exception found during execution: {str(e)}")
    finally:
        logger.info(f"========== CD Enable Disable file agent status process completed ==========")
        logger.info(f"Exit code = {return_code}")
        sys.exit(return_code)

if __name__ == '__main__':
    main()