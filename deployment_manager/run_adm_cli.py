# Main Entry Point
import argparse
import logging
import os
import sys
import traceback

from dotenv import load_dotenv

from app.api_gateway import ApiGateway
from app.logger import setup_logging
from app.models.interface_deployment_model import DeploymentStatus

setup_logging()

from app.util.common_util import get_root_path

logger = logging.getLogger(__name__)
logging.getLogger("urllib3.connectionpool").setLevel(logging.CRITICAL)

def main():
    try:
        def is_truthy(v):
            if isinstance(v, bool):
                return v
            # strings
            s = str(v).strip().lower()
            return s in {"true", "remove"}

        parser = argparse.ArgumentParser(
            description="Deploy interfaces on a given environment"
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

        root_path = ""
        try:
            root_path = get_root_path()
            logger.info(f"root_path: {root_path}")
        except Exception as e:
            logger.error("Failed to determine root path.")
            logger.debug(f"Error: {e}")
            sys.exit(1)

        # Check if .env file exists
        env_file_path = os.path.join(root_path, ".env")
        if not os.path.isfile(env_file_path):
            logger.error(f".env file not found at expected location: {env_file_path}")
            sys.exit(1)
        load_dotenv()

        try:
            git_pat = os.getenv("GIT_PERSONAL_ACCESS_TOKEN")
            # logger.info(f"GIT_PERSONAL_ACCESS_TOKEN: {git_pat}")
            if not git_pat:
                raise EnvironmentError("GIT_PERSONAL_ACCESS_TOKEN environment variable is not set.")

        except (EnvironmentError, FileNotFoundError) as e:
            logger.error("Configuration file error.")
            logger.debug(f"Error: {e}")
            sys.exit(1)

        # Parse arguments
        args = parser.parse_args()
        logger.info("======================= Loading required configuration started ========================== ")
        api_gateway = ApiGateway()
        env_config_service = api_gateway.load_required_configuration()
        logger.info("======================= Loading required configuration completed ========================== ")

        logger.info("======================= Interfaces deployment started ========================== ")
        logger.info(f"Deploying following interfaces on '{args.env}' environment with execution mode = '{args.execution_mode}'")

        env = env_config_service.get_environment(args.env.lower())
        validate_env(env, args)

        default_cd_rule = api_gateway.get_default_cdrule_config()
        interfaces = [(interface['name'], interface['cd_rule'], str(interface['deploy'])) for interface in env.interfaces if is_truthy(interface['deploy'])]
        payload = {
            "env_name": env.name,
            "mode": args.execution_mode,
            "requested_by": "admin",
            "interfaces": interfaces,
            "branch_name": env.environment_details['branch_name'],
            "repo_name": os.getenv("GIT_ARTIFACTS_REPO"),
            "deploy_config": env.deployment_config,
            "hosts": env.hosts,
            "default_cd_rule": default_cd_rule,
        }
        request = api_gateway.deploy(payload)
        return_code = 0
        if request.status == DeploymentStatus.FAILED:
            logger.error("Could not deploy all the interfaces successfully. Refer logs for more details.")
            logger.info("======================= Deployment completed with errors ========================== ")
            return_code = 1
        else:
            logger.info(f"Interfaces deployed successfully.")
            logger.info("======================= Deployment completed successfully ========================== ")
            return_code = 0

        logger.info(f"Exit code = {return_code}")
        sys.exit(return_code)
    except Exception as ex:
        logger.debug(f"Unexpected error: {ex}")
        logger.error(f"Unexpected failure during deployment of interfaces.{ex}")
        traceback.print_exc()
        sys.exit(1)

def validate_env(env, args):
    if env is None:
        logger.error(f"Environment '{args.env}' not found.")
        sys.exit(1)
    if env.env_errors:
        logger.error(f"Environment '{args.env}' contains errors: {env.env_errors}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("\nMissing required arguments: --env\n")
        print('Usage example: python run_adm_cli.py --env "dev" --execution-mode "preview"\n')
        print("Use --help to see all available options.\n")
        sys.exit(1)
    main()
