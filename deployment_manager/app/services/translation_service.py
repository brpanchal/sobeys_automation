import logging
import json
import re
from pathlib import Path
from typing import Union

from app import constants
from app.config_loader import AppConfig

logger = logging.getLogger(__name__)

class TranslationService:
    def __init__(self, config):
        self.deployment_config = config
        self.ignore_vars:list = self.get_ignored_variable_list()

    def  get_ignored_variable_list(self):
        config = AppConfig(constants.CONFIG_FILENAME)
        return config.get(constants.IGNORED_DEPLOY_CONFIG_VARIABLES, [])

    def load_config(self, env: str, config_dir: str = "./configs") -> dict:
        config_path = Path(config_dir) / f"{env}_config.json"
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found for environment: {env}")
        with open(config_path, "r") as f:
            return json.load(f)


    def replace_placeholders(self, value: str, config: dict) -> str:
        pattern = r"\${{\s*(\w+)\s*}}"

        def replacer(match):
            key = match.group(1)
            if key in self.ignore_vars:
                return match.group(0)
            if key in config:
                logger.debug(f"Replacing {key} with {config[key]}")
                return str(config[key])
            else:
                logger.error(f"Key '{key}' not found in deployment_config.")
                raise KeyError(f"Key '${{{key}}}' not found in deployment_config.")

        return re.sub(pattern, replacer, value)

    def recursive_replace(self, obj: Union[dict, list, str], config: dict) -> Union[dict, list, str]:
        if isinstance(obj, dict):
            return {k: self.recursive_replace(v, config) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.recursive_replace(item, config) for item in obj]
        elif isinstance(obj, str):
            return self.replace_placeholders(obj, config)
        else:
            return obj

    def translate_artifact(self, artifact: str) -> str:
        try:
            artifact_json = json.loads(artifact)
            translated_json = self.recursive_replace(artifact_json, self.deployment_config)
            return json.dumps(translated_json, indent=2)
        except json.JSONDecodeError:
            # If not JSON, treat as plain string
            return self.replace_placeholders(artifact, self.deployment_config)

if __name__ == "__main__":
    pass
