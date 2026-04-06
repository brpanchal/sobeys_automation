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
    if path and file_name:
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
                        raise ValueError(f"Invalid JSON in file {file_name} at given path {actual_file_path}")
                else:
                    return f.read()
        else:
            raise Exception(f"Node list file ({file_name}) not found at specified path ({actual_file_path})!")
    else:
        raise Exception(f"Either path ({path}) or filename({file_name}) is missing to load the configuration")


def check_node_list_file_and_validate_node_config(env):
    """
        Load node list json as per environment variable
        :return: sequence list of nodes along with cdws config
    """
    logger.debug(f"Reading node list json from {env}")
    if env.lower() in ENVIRONMENT:
        node_split = NODE_LIST_FILE.split(".")
        file_name = f"{node_split[0]}_{env}.{node_split[1]}"
    else:
        raise Exception(f"Environment not recognized. Please provide a valid environment. e.g.{ENVIRONMENT}.")
    # Read file and get json data from file
    node_list = read_file(file_name, PARENT_DIR, True)

    try:
        #checkpoint for node_data
        if (not node_list) or (len(node_list) == 0):
            raise Exception(f"Node json data not found in the node list file({file_name})!")
    except Exception as e:
        logger.debug(f"Error due to: {e}")
        raise Exception(f"Node list json data is not configured correctly in file ({file_name}):{e}")

    logger.info(f"Node list file({file_name}) found and json data validated successfully.")
    return node_list

def is_env_file_exist():
    """
    Check if env file exists
    :return: None if checkpoint valid otherwise it raise exception
    """
    #Check point for .env file
    env_path = Path(ENV_FILE)

    if env_path.is_file():
        logger.info("Environment file (.env) found and loaded successfully.")
    else:
        raise Exception("Environment (.env) file is missing in the utility directory!")

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
        help="Choose 'preview' to simulate changes or 'execute' to apply the changes."
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
        is_env_file_exist()
        node_list = check_node_list_file_and_validate_node_config(args.env)
        logger.info("========== Loading required configuration completed =============")
        status = fileagent_status_service(node_list, args)
        if status > 0:
            return_code = 1
    except Exception as e:
        logger.error(f"⛔ Unexpected exception found during execution: {str(e)}")
        return_code = 1
        raise Exception(f"⛔ Unexpected exception found during execution: {str(e)}")
    finally:
        logger.info(f"========== CD Enable Disable file agent status process completed ==========")
        logger.info(f"Exit code = {return_code}")
        sys.exit(return_code)


if __name__ == '__main__':
    main()
