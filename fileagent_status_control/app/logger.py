import logging
import os
import sys
from .constants import *
from datetime import datetime

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

log_path = os.path.join(PARENT_DIR, f"{NODE_INIT_BACKUP_PATH}{timestamp}")
log_file = f"{log_path}/App_{timestamp}.log"

# Ensure the logs directory exists
os.makedirs(log_path, exist_ok=True)

# Ensure UTF-8 output
sys.stdout.reconfigure(encoding="utf-8")
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
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter("%(asctime)s - %(message)s")
console_handler.setFormatter(console_formatter)

# Get the root logger and add the console handler
logger = logging.getLogger()
logger.addHandler(console_handler)
logger = logging.getLogger(__name__)