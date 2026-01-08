# app/logger.py
import logging.config
from datetime import datetime
from pathlib import Path

import yaml

from app.util.common_util import get_root_path


def setup_logging(config_path="app/logging.yaml"):
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f.read())

    # Always use absolute paths
    base_dir = get_root_path()
    logs_dir = base_dir / "logs"
    logs_dir.mkdir(exist_ok=True)

    # Generate timestamped filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = logs_dir / f"app_{timestamp}.log"

    # Update the YAML config dynamically
    config["handlers"]["file"]["filename"] = log_filename
    config["handlers"]["file"]["mode"] = "w"  # overwrite, not append

    # Apply logging config
    logging.config.dictConfig(config)
