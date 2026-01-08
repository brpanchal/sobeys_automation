import json
import unittest

from api_router import ApiRouter
from app.services.translation_service import TranslationService

class TestTranslationService(unittest.TestCase):
    def setUp(self):
        self.api_router = ApiRouter()
        self.api_router.load_required_configuration()
        selected_environment = self.api_router.get_environment("QA")
        if not selected_environment:
            raise RuntimeError(f"Error : No matching directory found {selected_environment}.")

        if selected_environment.env_errors:
            raise RuntimeError(f"Error : env_errors: {str(selected_environment.env_errors)}.")

        self.deployment_config = selected_environment.deployment_config
        self.service = TranslationService(self.deployment_config)

    def test_watchdir(self):
        watchdir_artifact = '{"watchDirList": {    \
                "/db2work/cma/outbox": {    \
                    "comments": "/db2work/cma/outbox",  \
                    "watchedDir": "${db2work_cma_outbox_spath}",    \
                    "monitorSubDirectories": false  \
                } }}'
        expected = '{"watchDirList": {    \
                "/db2work/cma/outbox": {    \
                    "comments": "/db2work/cma/outbox",  \
                    "watchedDir": "/db2work/cma/outbox",    \
                    "monitorSubDirectories": false  \
                } }}'
        self.assertEqual(json.loads(self.service.translate_artifact(watchdir_artifact)), json.loads(expected))

    def test_rulelist(self):
        rulelist_artifact = '{ "rules": [{"comments": "/db2work/cma/outbox","fileSizeEnabled": false,"filePathKeyvalues": "MATCH|${db2work_cma_outbox_spath}","procName": "EDWCMA01_SFG.cdp","ruleStatus": "Enabled","priority": 20,"filePathEnabled": true,"altFileName": "","procArgs": "&INFILE=%FA_FILE_FOUND. &FILENAME=%FA_NOT_PATH.","notifyUid": "","name": "F2F_EDWCMA01_CONDITION_EXT_004_SAPRMS01","fileSizeKeyvalues": "","lastModified": "Sun Mar 23 07:00:09 ADT 2025","procPriority": "1","fileNameKeyvalues": "CONTAINS|cma_condition_ext.${region_code_atl}.*.txt","procClass": "1","fileNameEnabled": true}]}'
        expected = '{ "rules": [{"comments": "/db2work/cma/outbox","fileSizeEnabled": false,"filePathKeyvalues": "MATCH|/db2work/cma/outbox","procName": "EDWCMA01_SFG.cdp","ruleStatus": "Enabled","priority": 20,"filePathEnabled": true,"altFileName": "","procArgs": "&INFILE=%FA_FILE_FOUND. &FILENAME=%FA_NOT_PATH.","notifyUid": "","name": "F2F_EDWCMA01_CONDITION_EXT_004_SAPRMS01","fileSizeKeyvalues": "","lastModified": "Sun Mar 23 07:00:09 ADT 2025","procPriority": "1","fileNameKeyvalues": "CONTAINS|cma_condition_ext.004.*.txt","procClass": "1","fileNameEnabled": true}]}'
        self.assertEqual(json.loads(self.service.translate_artifact(rulelist_artifact)), json.loads(expected))

    def test_codelist(self):
        codelist_artifact = '{"codes": [{   \
                    "senderCode": "UTLEST02|SAPNBW01",  \
                    "receiverCode": "dscoboh.____", \
                    "description": "F2FF_UTLEST02_DSCOBOH_AZURE_DL",    \
                    "text1": "SAPNBW01",    \
                    "text2": "",    \
                    "text3": "${com_nbw_in_exe}", \
                    "text4": "",    \
                    "text5": "",    \
                    "text6": "",    \
                    "text7": "",    \
                    "text8": "",    \
                    "text9": ""     \
                }]}'

        expected = '{"codes": [{   \
                    "senderCode": "UTLEST02|SAPNBW01",  \
                    "receiverCode": "dscoboh.____", \
                    "description": "F2FF_UTLEST02_DSCOBOH_AZURE_DL",    \
                    "text1": "SAPNBW01",    \
                    "text2": "",    \
                    "text3": "/com/NPQ/in/EXE", \
                    "text4": "",    \
                    "text5": "",    \
                    "text6": "",    \
                    "text7": "",    \
                    "text8": "",    \
                    "text9": ""     \
                }]}'

        self.assertEqual(json.loads(self.service.translate_artifact(codelist_artifact)), json.loads(expected))

    def test_invalid_watchdir(self):
        invalid_watchdir_artifact = '{"watchDirList": {    \
                "/db2work/cma/outbox": {    \
                    "comments": "/db2work/cma/outbox",  \
                    "watchedDir": "${db2work_1cma_outbox_spath}",    \
                    "monitorSubDirectories": false  \
                } }}'

        with self.assertRaises(KeyError) as context:
            self.service.translate_artifact(invalid_watchdir_artifact)
        self.assertIn("Key \'${db2work_1cma_outbox_spath}\' not found in deployment_config", str(context.exception))

    # 1) Space inbetween dynamic variable: Ex: ${db2work_ cma_outbox_spath}
    def test_invalid_1(self):
        input = "${db2work_ cma_outbox_spath}"
        self.assertEqual(self.service.translate_artifact(input), input)

    # 2)  $db2work$db2work
    def test_invalid_2(self):
            input = "$db2work$db2work"
            self.assertEqual(self.service.translate_artifact(input), input)

    # 3)  ${db2work
    def test_invalid_3(self):
            input = "${db2work"
            self.assertEqual(self.service.translate_artifact(input), input)

    # 4)  $db2work}
    def test_invalid_4(self):
            input = "$db2work}"
            self.assertEqual(self.service.translate_artifact(input), input)

    # 5)  {db2work}
    def test_invalid_5(self):
            input = "{db2work}"
            self.assertEqual(self.service.translate_artifact(input), input)

    # 6)  $$db2work
    def test_invalid_6(self):
            input = "$$db2work"
            self.assertEqual(self.service.translate_artifact(input), input)

    # 7)  {$db2work}
    def test_invalid_7(self):
            input = "{$db2work}"
            self.assertEqual(self.service.translate_artifact(input), input)

    # 8)  $db2work
    def test_invalid_8(self):
            input = "$db2work"
            self.assertEqual(self.service.translate_artifact(input), input)

    # 9)  $db2 work
    def test_invalid_9(self):
            input = "$db2 work"
            self.assertEqual(self.service.translate_artifact(input), input)

    # 10)  {db2 work}
    def test_invalid_10(self):
            input = "{db2 work}"
            self.assertEqual(self.service.translate_artifact(input), input)

    # 11) ignore this case : dsciuord.${MM}${DD}.$GUID5
    def test_invalid_MM_DD(self):
            input = "dsciuord.${MM}${DD}.$GUID5"
            self.assertEqual(self.service.translate_artifact(input), input)


if __name__ == '__main__':
    unittest.main()
