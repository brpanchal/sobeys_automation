#variables

LOG_FILE_PATH = "./logs"
PARENT_DIR="./Artifacts/"
NODE_INIT_BACKUP_PATH = "NODE_INIT_BACKUP/"
NODE_LIST_FILE = "NODE_LIST_FILE"
FILEAGENT_REGEX = r'(?i)(?P<prefix>\bfileagent\.enable\s*=\s*)(?P<val>[YN])\b'
CDFA_REGEX = r'(?i)(?P<prefix>\bcdfa\.enable\s*=\s*)(?P<val>[yn])\b'
FILEAGENT_KEY = "fileagent.enable"
FILEAGENT_PREFIX = 'File Agent'
CDFA_KEY = 'cd.file.agent:cdfa.enable'
STATUS_MSG = ["Not mentioned", "Invalid value"]
TABLE_HEADER = ["Sr. No.", "Node", "Hostname", "OS Type", "FileAgent Key", "Current FileAgent Status", "New FileAgent Status", "Action/Status"]
TITLE = "FileAgent status details for all nodes"
OS_TYPE = "os_type"
HOSTNAME = "hostname"
NODE = 'node'
INITPARMSDATA = 'initParmsData'
STATUS_LIST = ['y', 'n']