#Varibales
from urllib.error import HTTPError

ENV = "dev"
EXECUTION_MODE = "preview"
BASE_URL = "http://dummy.com:8080"
TEST_DATA_PATH = "/testdata"
FILENAME = 'NODE_LIST_FILE'
FILEPATH = './Artifacts/'
NODE_LIST = ["node", "hostname", "os_type"]
FILE_ERROR= "Error reading nodes list json file"
PROCESS_LIST_ENDPOINT = 'cdwebconsole/svc/processlibrary/list'
PROCESS_DATA_ENDPOINT = 'cdwebconsole/svc/processlibrary?processFileName='
WD_N_RULE_ENDPOINT = 'cdwebconsole/svc/faconfiguration/export'
CD_SIGN_ON = 'CDWS sign_on Successful!!'
CD_SIGN_ON_MSG = "Sign_on log line not found in logs"
EXPECTED_PAYLOAD = { "node": "Dummy2", "hostname": "dummy2.com", "os_type": "windows system" }
PAYLOAD_EXCEPTION = "Unexpected exception during payload"
WD_EXPECTED = 'watchDirList Artifacts for node'
WD_LOG_MSG = "watchDirList log line not found in logs"
RULE_EXPECTED = 'ruleList Artifacts for node'
RULE_LOG_MSG = "ruleList log line not found in logs"
PROCESS_EXPECTED = 'PROCESSFILE'
PROCESS_LOG_MSG = "PROCESSFILE log line not found in logs"
START_BACKUP_EXPECTED= 'Started backup of CD artifacts for node Sample'
START_BACKUP_LOG_MSG = "Start backup log line not found in logs"
COMPLETE_BACKUP_EXPECTED= 'Completed backup of CD artifacts for node Sample'
COMPLETE_BACKUP_LOG_MSG = "Complete Backup log line not found in logs"
PREVIEW_EXPECTED = 'Found existing CD artifacts details for node'
PREVIEW_LOG_MSG = "Artifacts log line not found in logs"
BACKUP_SUMMARY_EXPECTED= 'Backup Summary Details'
BACKUP_SUMMARY_LOG_MSG = "Summary detail log line not found in logs"
STATUS_EXPECTED= 'Success: 3    Failed: 0'
STATUS_LOG_MSG = "Status log line not found in logs"
TABLE_EXPECTED= 'Node process succeeded'
TABLE_LOG_MSG = "Table log line not found in logs"
EXECUTION_MODE_EXPECTED= 'Updating CD artifacts for node'
EXECUTION_MODE_LOG_MSG = "Update artifacts log line not found in logs"
COMPLETE_BACKUP_MSG = 'Completed backup of CD artifacts for node'
COMPLETE_BACKUP_LOG = "Complete backup artifacts log line not found in logs"
PROCESS_FAILED_EXPECTED= 'Processing failed for CD artifacts due to'
PROCESS_FAILED_LOG_MSG = "Processing failed log line not found in logs"
CD_REWIND_EXCEPTION = "Unexpected exception found during execution: 'NoneType' object is not iterable"
HTTPERROR_EXPECTED= 'HTTPError exception during GET'
ERROR_400 = '400 Client Error'
ERROR_404 = '404 Client Error'
REQUEST_EXCEPTION = 'Request exception'
ERROR_FOUND ='Error found'
UNEXPECTED_ERROR = 'Unexpected exception found during GET'
UNEXPECTED_ERROR_CODE = 'Unexpected exception found during sign_on'
ERROR_500 = '500 Server error exception raised'
HTTP_ERROR_TEXT = 'HTTPError exception!! Text'
HTTP_ERROR_CODE = 'HTTPError exception during sign_on'
NO_ARTIFACTS = '— No Artifacts —'
ERROR_400_MSG = "400 Client Error: Not Found"
ERROR_404_MSG ="404 Client Error: Not Found"
ERROR_500_MSG="500 Server error exception raised"



