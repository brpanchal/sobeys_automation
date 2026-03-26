#Varibales

ENV = "dev"
EXECUTION_MODE = "preview"
BASE_URL = "http://dummy.com:8080"
TEST_DATA_PATH = "tests/testdata/"
FILENAME = 'NODE_LIST_FILE'
INITFILENAME = 'initparms.json'
FILEPATH = './Artifacts/'
NODE_LIST = ["node", "hostname", "os_type", 'fileagent.enable']
FILE_ERROR= "Error reading nodes list json file"
CD_SIGN_ON = 'CDWS sign_on Successful!!'
CD_SIGN_ON_MSG = "Sign_on log line not found in logs"
CD_SIGN_ON_FAILED = 'CD Sign-on Failed!! status_code: 400'
HOST_DICT_1 = { "node": "Dummy1", "hostname": "dummy1.com", "os_type": "unix system" }
HOST_DICT_2 = { "node": "Dummy2", "hostname": "dummy2.com", "os_type": "windows system" }
HOST_DICT_3 = { "node": "Dummy3", "hostname": "dummy3.com", "os_type": "aix system" }
EXPECTED_PAYLOAD = 'y'
EXPECTED_PAYLOAD_N = 'n'
PAYLOAD_EXCEPTION = "pop expected at most 1 argument, got 2"
START_BACKUP_EXPECTED= 'Started backup of initparams details for node Sample'
START_BACKUP_LOG_MSG = "Start backup log line not found in logs"
COMPLETE_BACKUP_EXPECTED= 'Completed backup of initparams details for node Sample'
COMPLETE_BACKUP_LOG_MSG = "Complete Backup log line not found in logs"
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
RESPONSE_DATA = {"INITPARMS": [{"messageCode": 200,"message": "Init Parms data has been updated successfully"}]}



