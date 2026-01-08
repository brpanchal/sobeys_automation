import logging

import yaml
import os

from app import constants

logger = logging.getLogger(__name__)

class AppConfig:
    _instance = None  # Singleton instance

    def __new__(cls, config_path=constants.CONFIG_FILENAME):
        if cls._instance is None:
            cls._instance = super(AppConfig, cls).__new__(cls)
            cls._instance._load_config(config_path)
        return cls._instance

    def _load_config(self, config_path):
        logger.info(f"Loading configuration from {config_path}")
        if not os.path.exists(config_path):
            logger.error(f"Configuration file not found: {config_path}")
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(config_path, "r") as file:
            self.config = yaml.safe_load(file)

    def get(self, key_path, default=None):
        """Fetch nested keys using dot notation, e.g. get('database.host')"""
        keys = key_path.split(".")
        value = self.config
        for key in keys:
            value = value.get(key, None)
            if value is None:
                return default
        return value
