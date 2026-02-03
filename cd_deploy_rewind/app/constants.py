#variables
from datetime import datetime

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

LOG_FILE_PATH = f"./CDBACKUP_{timestamp}"
PARENT_DIR="./Artifacts/"
CD_BACKUP_PATH = f"/CDBACKUP_{timestamp}"
CDP_BACKUP_PATH = "CDP"
NODE_LIST_FILE = "NODE_LIST_FILE"
SYSTEMS = ["windows", "aix", "unix"]
CD_RULE_N_WATCHDIR_FILE = "RULES_AND_WATCHDIR.json"
CD_PROCESS_LIST_FILE = "PROCESS_LIST.json"
PROCESS_FILE_NAME = "processFileName"
ROOT_TYPE = ["watchDirList", "ruleList", "PROCESSFILES"]
WATCHDIR_COL = ["watchedDir", "comments", "monitorSubDirectories"]
RULE_LIST_COL = ["name", "comments", "ruleStatus", "procArgs", "procName"]
PROCESS_LIST_COL = "fileName"
SUMMARY_COL = ["Sr.No.", "Node", "Status", "Message", "Duration", "Start Time - End Time (HH:MM:SS)"]
SUMMARY_TITLE = "Backup Summary Details"
