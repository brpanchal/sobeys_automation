import logging
import os
from .constants import *

# Ensure the logs directory exists
logdir = f"{PARENT_DIR}/{LOG_FILE_PATH}"
os.makedirs(logdir, exist_ok=True)

log_file = f"{logdir}/{LOG_FILE_PATH}.log"

# Configure the logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    datefmt= "%Y-%m-%d %H:%M:%S",
    filename=log_file,
    filemode="a",
    encoding="utf-8"
)

# Add console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter("%(asctime)s - %(message)s")
console_handler.setFormatter(console_formatter)

# Get the root logger and add the console handler
logger = logging.getLogger()
logger.addHandler(console_handler)
logger = logging.getLogger(__name__)