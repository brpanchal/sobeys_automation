import os
import json
import argparse
import sys
from dotenv import load_dotenv
from app.logger import logger
from app.constants import *
from app.fileagent_status_app import fileagent_status_service
from pathlib import Path
load_dotenv()


def read_file(file_name, path, json_type=False):
    """
        Read file and get the json or plain text data
        :param file_name: file name
        :param path: file path
        :param json_type: json(True) or plain(False)
        :return: json or plain text
    """
    actual_file_path = path + file_name
    path = Path(actual_file_path)

    if path.is_file():
        logger.debug(f"Reading file {file_name} from {actual_file_path}")
        with open(actual_file_path, 'r') as f:
            if json_type:
                try:
                    return json.load(f)
                except json.JSONDecodeError as e:
                    logger.debug("Invalid JSON:%s", e)
                    raise ValueError(f"Invalid JSON in file {file_name} from {actual_file_path}")
            else:
                return f.read()
    else:
        raise Exception("Node list json file not found in the given path!")


def read_node_list_json(env):
    """
        Read node list json and append to sequence list
        :return: sequence list
    """
    try:
        logger.debug(f"Reading node list json from {env}")
        if env.lower() in ENVIRONMENT:
            node_split = NODE_LIST_FILE.split(".")
            file_name = f"{node_split[0]}_{env}.{node_split[1]}"
        else:
            raise Exception(f"Environment not recognized. Please provide a valid environment. e.g.{ENVIRONMENT}.")
        # Read file and get json data from file
        node_list_with_config = read_file(file_name, PARENT_DIR, True)
        logger.info("Node list file found and json validated successfully.")
        return node_list_with_config
    except Exception as e:
        raise Exception(f"Error due to: {e}")

def env_config_node_file_exists(node_list_with_config):
    #Check point for .env file
    env_path = Path(ENV_FILE)

    if env_path.is_file():
        logger.info("Environment file found and loaded successfully.")
    else:
        raise Exception(".env file is missing in the directory!")

    try:
        #Checkpoint for config data
        config = node_list_with_config.get("config", None)
        if config:
            if config.get('cdws_url', None) and config.get('cdws_port', None):
                logger.debug("Configurations for cdws portal is available!")
            else:
                raise Exception("cdws_url and cdws_port are required to sign on cdws portal!")
        else:
            raise Exception("Config (cdws_url and cdws_port) are missing in config and node list file.")

        #checkpoint for node_data
        nodes = node_list_with_config.get("nodes", None)
        if (not nodes) or (len(nodes) == 0):
            raise Exception("Node json data not found in the node list file!")
    except Exception as e:
        logger.debug(f"Error due to: {e}")
        raise Exception(f"Configuration or node list json data is not configured correctly:{e}")

def input_parser():
    """
        Parse input arguments
        :return: input parser
    """
    parser = argparse.ArgumentParser(
        description="Enable Disable File Agent Status for node on CD on a given environment"
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
    """
        Main function to start the execution when command line arguments are given with command
    """
    args = input_parser()
    return_code = 0
    try:
        logger.info(
            f"========== CD Enable Disable file agent status process started: Env={args.env}, Execution mode={args.execution_mode} ==========")

        logger.info("========== Loading required configuration started =============")
        node_list_with_config = read_node_list_json(args.env)
        env_config_node_file_exists(node_list_with_config)
        logger.info("========== Loading required configuration completed =============")
        status = fileagent_status_service(node_list_with_config, args)
        if status > 0:
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
