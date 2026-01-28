import os
import  json
import argparse
from dotenv import load_dotenv
from collections import defaultdict
from app.logger import logger
from app.constants import *
from app.cd_rewind_service import run_cd_rewind_service

load_dotenv()

def read_file(file_name, path,  json_type=False):
    if file_name:
        with open(path+os.getenv(file_name), 'r') as f:
            return json.load(f) if json_type else f.read()
    return None

def read_node_list_json():
    try:
        node_list = read_file(NODE_LIST_FILE, PARENT_DIR, True)
        buckets = defaultdict(list)
        for node in node_list:
            os_type = node.get("os_type", "").lower()
            if SYSTEMS[0] in os_type:
                buckets[SYSTEMS[0]].append(node)
            elif SYSTEMS[1] in os_type:
                buckets[SYSTEMS[1]].append(node)
            else:
                buckets[SYSTEMS[2]].append(node)
    except Exception as e:
        raise Exception(f"Error reading nodes list json file: {e}")

    return [buckets[SYSTEMS[0]], buckets[SYSTEMS[2]], buckets[SYSTEMS[1]]]

def input_parser():
    parser = argparse.ArgumentParser(
        description="Backup and Restore CD data on a given environment"
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
    try:
        logger.info(f"========== CD rewind process started: Env={args.env}, Execution mode={args.execution_mode} ==========")

        logger.info("========== Loading required configuration started =============")
        node_list_json = read_node_list_json()
        logger.info("========== Loading required configuration completed =============")
        run_cd_rewind_service(node_list_json, args)
    except Exception as e:
        raise Exception(f"Unexpected exception found during execution: {str(e)}")
    finally:
        logger.info(f"========== CD rewind processs completed ==========")

if __name__ == '__main__':
    main()