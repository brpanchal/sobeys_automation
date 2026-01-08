CONFIG_FILENAME = "config.yaml"

# Configuration files related constants
CONFIG_FILE_INTERFACES = "interfaces.csv"
CONFIG_FILE_DEPLOY_CONFIG = "deploy_config.json"
CONFIG_FILE_HOST = "host.json"

ENV_CONFIG_PATH = "app.env_config_path"
IGNORED_DEPLOY_CONFIG_VARIABLES = 'ignored_deploy_config_vars'

DEPLOYMENT_HISTORY_DATA_DIR = "app.deployment_history_data_dir"
DEPLOYMENT_REQUESTS_FILE = "deployment_requests.csv"
DEPLOYMENT_RESPONSES_FILE = "deployment_responses.csv"
DEPLOYMENT_ERRORS_FILE = "deployment_errors.csv"

DEFAULT_CD_RULE = "app.default_cd_rule"
RULE_STATUS = 'ruleStatus'
RULE_STATUS_MAPPING = {
    'enable': 'Enabled',
    'disable': 'Disabled',
    'draft': 'Draft'
}

BRANCH_PARAMS_RECURSIVE = {
        'recursionLevel': 'full',
        'versionDescriptor.versionType': 'branch',
        'versionDescriptor.version': '',
        'api-version': '7.0'
    }

BRANCH_PARAMS_SINGLE = {
            'scopePath': '/',  # root folder
            'versionDescriptor.versionType': 'branch',
            'versionDescriptor.version': '',
            'recursionLevel': 'OneLevel',
            'api-version': '7.1'
        }
MANDATE_ARTIFACTS = ['ConnectDirect', 'Interface', 'ConnectDirect/CDP']
INTERFACE_ARTIFACTS = ['Interface/<interface>', 'Interface/<interface>/interface_metadata.json', 'Interface/<interface>/SFG']
PATTERN = r"^Add rule failed, Rule:\s*([A-Za-z0-9_]+)\s*already exists\.$"
RULE_KEYS = ['comments', 'fileSizeEnabled', 'filePathKeyvalues', 'procName', 'ruleStatus', 'filePathEnabled', 'altFileName', 'procArgs', 'notifyUid', 'fileSizeKeyvalues', 'fileNameKeyvalues', 'fileNameEnabled']
MATCH_MAP = {"true": True, "false": False}