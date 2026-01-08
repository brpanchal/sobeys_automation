import json
import logging
import os
from typing import Dict

from dotenv import load_dotenv

from app import constants
from app.models.environment import Environment
from app.services.git_connector import GitConnector

logger = logging.getLogger(__name__)
load_dotenv()

must_required_files = {constants.CONFIG_FILE_INTERFACES, constants.CONFIG_FILE_DEPLOY_CONFIG,
                  constants.CONFIG_FILE_HOST}

class EnvironmentConfigService:
    """Singleton class that stores all environment configs in memory."""
    _instance = None

    def __new__(cls, config_file: str = None):
        if cls._instance is None:
            cls._instance = super(EnvironmentConfigService, cls).__new__(cls)
            cls._instance.environments = {}
            cls._instance.git_connector = GitConnector()
            if config_file:
                cls._instance._load_from_file(config_file)
        return cls._instance

    def _get_path_with_env(self, path, env_name:str):
        if isinstance(path, set):
            return {'/'+env_name.upper()+'/'+file for file in path}
        return f"/{env_name.upper()}/{path}"

    def _load_from_file(self, config_file: str):
        """Load all environments from JSON file once into memory."""
        logger.info(f"Loading environment config from {config_file}")
        if not os.path.exists(config_file):
            raise FileNotFoundError(f"Environment Config file not found: {config_file}")

        with open(config_file, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                # logger.error(f"Invalid JSON format in config file '{config_file}': {e}")
                raise ValueError(f"Invalid JSON format in config file: {config_file}") from e

        enabled_envs = [env for env in data if env.get('enabled', False)]
        logger.info(f"enabled environments:{enabled_envs}")

        names = [item["name"] for item in enabled_envs]
        duplicates = set([name for name in names if names.count(name) > 1])

        if duplicates:
            raise Exception("ERROR: Duplicate names found in env_config.json:", ", ".join(duplicates))

        for env in enabled_envs:
            org_env_name = env['name']
            env_name = org_env_name.lower()
            branch_name = env['branch_name'] if env.get('branch_name') else ""
            repo_name = os.getenv("GIT_DEPLOY_CONFIG_REPO")
            logger.info(f"environment: {env_name}, branch_name: {branch_name}")
            searched_files = self.search_files(branch_name, repo_name, org_env_name)
            errors = []
            deploy_config_file_contents = dict()
            host_file_contents = dict()
            interfaces_file_contents = dict()
            if searched_files:
                missing_files, required_files = self.validate_required_files(searched_files, org_env_name)

                if missing_files:
                    logger.warning(f"Missing required files: {missing_files} under repo: {repo_name}, branch: {branch_name}")
                    errors.append(f"Missing required files: {missing_files} under repo: {repo_name}, branch: {branch_name}")
                else:
                    interfaces_file_contents = self.git_connector.read_csv_file(repo_name, self._get_path_with_env(constants.CONFIG_FILE_INTERFACES, org_env_name))

                    deploy_config_file_contents = self.git_connector.read_json_file(repo_name, self._get_path_with_env(constants.CONFIG_FILE_DEPLOY_CONFIG, org_env_name))

                    host_file_contents = self.git_connector.read_json_file(repo_name, self._get_path_with_env(constants.CONFIG_FILE_HOST, org_env_name))

                env = Environment(name=env_name, environment_details=env,
                                  deployment_config=deploy_config_file_contents,
                                  hosts=host_file_contents, interfaces=interfaces_file_contents, env_errors=errors)
            else:
                errors.append(env_name)
                msg = f"Missing required files {must_required_files} under repo: {repo_name}, branch: {branch_name}"
                logger.error(msg)
                errors.append(msg)

                env = Environment(name=env_name, environment_details=env,
                                  deployment_config=deploy_config_file_contents,
                                  hosts=host_file_contents, interfaces=interfaces_file_contents, env_errors=errors)
            self.environments[env_name] = env


    def get_environment(self, env_name: str) -> Environment:
        """Get one environment by name."""
        return self.environments.get(env_name)

    def get_all_environments(self) -> Dict[str, Environment]:
        """Return all environments stored in memory."""
        return self.environments

    def reload(self, config_file: str):
        """Clear and reload environments (optional)."""
        self.environments.clear()
        self._load_from_file(config_file)

    # Search for directories matching the env_name
    def search_files(self, branch_name, repo_name, directory):
        self.git_connector.update_branch_name(branch_name)
        file_list = self.git_connector.fetch_file_list_from_dir(repo_name, directory, branch_name)
        return file_list

    # Validate required files in the selected directory
    def validate_required_files(self, existing_files, env_name):
        required_files = self._get_path_with_env(must_required_files, env_name)
        missing_files = required_files - set(existing_files)
        return missing_files, must_required_files

    def __repr__(self):
        return f"EnvironmentConfigManager(environments={list(self.environments.keys())})"
