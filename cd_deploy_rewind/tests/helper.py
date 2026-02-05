from tests.constants import *
from unittest.mock import patch, MagicMock

def mock_cd_rewind(x, y):
    print("mock_cd_rewind")

def mock_cd_rewind_exception(x, y):
    print("mock_cd_rewind_exception")
    raise Exception("Unexpected exception found during execution: boom")

def mock_request(*args, **kwargs):
    #print("Mocked request", args, kwargs)
    # Build a fake response whose raise_for_status() is a no-op
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    if 'cdwebconsole/svc/faconfiguration/export' in args[1]:
        data =kwargs.get('wd_rule_data')
        fake_resp.json.return_value = data
        fake_resp.text = str(data)
    elif 'cdwebconsole/svc/processlibrary/list' in args[1]:
        data = kwargs.get('process_list')
        fake_resp.json.return_value = data
        fake_resp.text = str(data)
    elif 'cdwebconsole/svc/processlibrary?processFileName=' in args[1]:
        data = kwargs.get('process_data')
        fake_resp.json.return_value = data
        fake_resp.text = str(data)
    else:
        fake_resp.json.return_value = {}
        fake_resp.text = str({})
    fake_resp.raise_for_status = MagicMock()  # <-- no exception
    return fake_resp