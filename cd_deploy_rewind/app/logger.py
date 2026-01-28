import logging
import os
from .constants import *
from datetime import datetime

# Ensure the logs directory exists
os.makedirs(LOG_FILE_PATH, exist_ok=True)

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = f"{LOG_FILE_PATH}/app_{timestamp}.log"

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