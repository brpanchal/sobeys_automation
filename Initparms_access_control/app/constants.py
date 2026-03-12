#variables

LOG_FILE_PATH = "./logs"
PARENT_DIR="./Artifacts/"
NODE_INIT_BACKUP_PATH = "NODE_INIT_BACKUP/"
NODE_LIST_FILE = "NODE_LIST_FILE"
SYSTEMS = ["windows", "aix", "unix"]
FILEAGENT_REGEX = r'(?i)(?P<prefix>\bfileagent\.enable\s*=\s*)(?P<val>[YN])\b'
CDFA_REGEX = r'(?i)(?P<prefix>\bcdfa\.enable\s*=\s*)(?P<val>[yn])\b'
FILEAGENT_KEY = "fileagent.enable"
CDFA_KEY = 'cd.file.agent:cdfa.enable'
PREVIEW_ACTION = ["Skip", "Skipped"]
EXECUTE_ACTION = ["Update", "Updated"]
STATUS_MSG = ["Not mentioned", "Invalid value"]
TABLE_HEADER = ["Sr. No.", "Node", "OS Type", "FileAgent Key", "Current FileAgent Status", "New FileAgent Status", "Action/Status"]
TITLE = "Initparms fileAgent details for all nodes"
