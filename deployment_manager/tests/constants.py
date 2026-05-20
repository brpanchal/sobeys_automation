#variable
TEST_DATA_PATH = "/test_data"
ruleStatus='Disabled'
BASE_URL = "http://dummy.com:8080"
ENV = "dev"
NODE_DATA = {"node":"abc", "hostname":"abc.com", "os_type":"unix", "password":"default"}
PSWD_EXCEPTION_DATA = {"DEV_ABC_USER": "test-key", "DEV_ABC_PASSWORD": "test-value", "DEV_CD_UNIX_PORT":"0"}
procName = 'TEST01_SFG.cdp'
TEST_CDP_NAME = 'TEST66.cdp'
TEST_WD = '/test_exe_t21/dat'
MATCHED_CDP = "TEST66_SFG.cdp"
MATCHED_WD = "/test/home/rbh/in"
EXECUTION_TYPE = ['preview', 'execute']
CONSUMER_CODE_LIST = "SBYS_FW_IDENTIFY_CONSUMER"
CD_CODE_LIST = "SBYS_FW_DELIVERY_CD"
GEN_CODE_LIST = "SBYS_FW_DELIVERY_GEN"
WSMQ_CODE_LIST = "SBYS_FW_DELIVERY_WSMQ"
EMAIL_CODE_LIST = "SBYS_FW_EMAIL"
SFTP_CODE_LIST = "SBYS_FW_DELIVERY_SFTP"
DB_CODE_LIST = "SBYS_FW_DELIVERY_DB"
NODE_KEYS = ["CDWS base_url", "Connect:Direct Properties", "os_type", "Host", "Port", "Credential"]
PATTERN = ["NO_RULE", "NO_GET_RULES", "NO_MATCH", "PARTIAL_MATCH", "FULL_MATCH", "CDP", "SIGNOUT" ]
RULE_EXCEP = "Rule name not provided or missing in the supplied CD rule list."
GET_RULE_EXCEP = "Skipping creation of File Agent rule: CD get_rules failed."
RULE_JSON_EXCEP = "Failed to deploy Rule, RuntimeError:"
INTERFACE_NAME = "F2F_TEST_DOCK_RSCQUE"
RULE_PREVIEW_LOG = "DEBUG:app.services.cd_service:Rule_Payload:"
RULE_UPDATE_LOG = "Rule updated successfully"
RULE_INSERT_LOG = "Rule inserted successfully"
ERROR_400_MSG = "400 Client Error: Not Found"
ERROR_404_MSG ="404 Client Error: Not Found"
ERROR_500_MSG="500 Server error exception raised"
HTTPERROR_EXPECTED= 'HTTPError exception during GET'
ERROR_400 = '400 Client Error'
ERROR_404 = '404 Client Error'
REQUEST_EXCEPTION = 'Request exception'
ERROR_FOUND ='Error found'
HTTP_ERROR = "HTTPError exception Text"
UNEXPECTED_ERROR = 'Unexpected exception found during GET'
UNEXPECTED_ERROR_CODE = 'Unexpected exception found during sign_on'
ERROR_500 = '500 Server error exception raised'
HTTP_ERROR_TEXT = 'HTTPError exception!! Text'
HTTP_ERROR_CODE = 'HTTPError exception during sign_on'
CD_SIGN_ON = 'CDWS sign_on Successful!!'
CD_SIGN_ON_MSG = "Sign_on log line not found in logs"
CD_SIGN_ON_FAILED = 'CD Sign-on Failed!! status_code: 400'
B2BI_HTTP_ERROR = "Failed to retrieve codelist. Status code:"
B2BI_REQ_EXCEPTION = "Request error while fetching codelist TEST01: 404 Client Error: Not Found"
B2BI_INSERT_REQ_EXCEPTION = "Request error while inserting codelist entry : 404 Client Error: Not Found"
B2BI_REMOVE_REQ_EXCEPTION = "Request error while remove codelist entry : 404 Client Error: Not Found"
METADATA_PATH = f"Interface/{INTERFACE_NAME}/interface_metadata"
SFG_PATH = f"Interface/{INTERFACE_NAME}/SFG/SBYS_FW_IDENTIFY_CONSUMER"
CDP_PATH = f"ConnectDirect/CDP/TEST_SFG.cdp"
RULE_PATH = "FULL_MATCH_RULE_PAYLOAD.json"
WD_PATH = "WD_PAYLOAD_DATA.json"
CD_FILES = ["WatchDirectory.json", "Rule_List.json", "ConnectDirect"]
PAYLOAD = {
            "env_name": ENV,
            "mode": EXECUTION_TYPE[0],
            "requested_by": "admin",
            "interfaces": [(INTERFACE_NAME, "enable", "True"), (INTERFACE_NAME, "enable", "Remove")],
            "branch_name": "dev",
            "repo_name": "Sterling-Artifacts",
            "deploy_config": {"env": "dev", "db2work_ops_outbox": ""},
            "hosts": {'hosts': [{'hostname': 'mullet.sobeys.com', 'nodename': 'EDWCMA01', 'os': 'unix', 'password': 'default'}]},
            "default_cd_rule": "Disabled",
        }
CODELISTS = [f"interface/{INTERFACE_NAME}/SBYS_FW_IDENTIFY_CONSUMER.json",
                              f"interface/{INTERFACE_NAME}/SBYS_FW_DELIVERY_CD.json",
                              f"interface/{INTERFACE_NAME}/SBYS_FW_DELIVERY_GEN.json",
                              f"interface/{INTERFACE_NAME}/SBYS_FW_DELIVERY_SFTP.json",
                              f"interface/{INTERFACE_NAME}/SBYS_FW_DELIVERY_WSMQ.json",
                              f"interface/{INTERFACE_NAME}/SBYS_FW_DELIVERY_FILESYSTEM.json",
                              f"interface/{INTERFACE_NAME}/SBYS_FW_DELIVERY_DB.json",
                              f"interface/{INTERFACE_NAME}/SBYS_FW_DELIVERY_AZUREFILESTORAGE.json",
                              f"interface/{INTERFACE_NAME}/SBYS_FW_COLLECT_SFTP.json",
                              f"interface/{INTERFACE_NAME}/SBYS_FW_EMAIL.json",
                              ]
