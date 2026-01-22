#variable
TEST_DATA_PATH = "/test_data"
ruleStatus='Disabled'
procName = 'EDWMBS01_SFG_1.cdp'
PATTERN = ["NO_RULE", "NO_GET_RULES", "NO_MATCH", "PARTIAL_MATCH", "FULL_MATCH", "CDP", "SIGNOUT" ]
RULE_EXCEP = "Rule name not provided or missing in the supplied CD rule list."
GET_RULE_EXCEP = "Skipping creation of File Agent rule: CD get_rules failed."
RULE_JSON_EXCEP = "Failed to deploy Rule, RuntimeError:"
INTERFACE_NAME = "F2F_RSCQUE66_CROSS_DOCK_RSCQUE211"
RULE_PREVIEW_LOG = "DEBUG:app.services.cd_service:Rule_Payload:"
RULE_UPDATE_LOG = "Rule updated successfully"
RULE_INSERT_LOG = "Rule inserted successfully"
