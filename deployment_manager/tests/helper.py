import os
import json
from tests.constants import *
from unittest.mock import patch, MagicMock
import requests

def read_test_data(data_type=None):
    if data_type:
        with open(os.path.join(os.path.dirname(__file__)+TEST_DATA_PATH, data_type+".json")) as f:
            data_list = f.read()
    else:
        data_list = {}
    return json.loads(data_list)

def read_git_file(*args, **kwargs):
    direct_path = kwargs.get("directpath")
    file_path = kwargs.get("file_path")
    json_type = kwargs.get("json_type", True)
    if direct_path:
        with open(os.path.join(os.path.dirname(__file__) + TEST_DATA_PATH, direct_path)) as f:
            data_list = f.read()
            if not json_type:
                return data_list
            return json.loads(data_list)
    elif "interface_metadata" in file_path:
        with open(os.path.join(os.path.dirname(__file__) + TEST_DATA_PATH, file_path)) as f:
            data_list = f.read()
            return json.loads(data_list)

    if file_path:
        if CD_FILES[0] in file_path:
            return kwargs.get("wd_data")
        elif CD_FILES[1] in file_path:
            return kwargs.get("rule_data")
        elif CD_FILES[2] in file_path:
            return kwargs.get("cdp_data")

    return {}

def mock_func_request(*args, **kwargs):
    #print("Mocked request", args, kwargs)
    data = kwargs.get("node") if kwargs.get("node") else {}
    status = kwargs.get("status") if kwargs.get("status") else True
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = data
    fake_resp.text = str(data)
    fake_resp.status = status
    fake_resp.raise_for_status = MagicMock()  # <-- no exception
    return fake_resp

# def mock_failed_request(*args, **kwargs):
#     #print("Mocked request", args, kwargs)
#     fake_resp = MagicMock()
#     fake_resp.status_code = 200
#     fake_resp.json.return_value = "Not Found"
#     fake_resp.text = "Not Found"
#     fake_resp.status = False
#     fake_resp.raise_for_status = MagicMock()  # <-- no exception
#     return fake_resp

def mock_data(param=None, data=None):
    #print("Mocked for", param)
    if param == PATTERN[0]:
        return True, {}
    elif param in PATTERN[6]:
        return True, param
    elif (param in PATTERN[2:6]) and data:
        return True, data
    return None, []

def mock_request(*args, **kwargs):
    #print("Mocked request", args, kwargs)
    rule_out=None
    # Build a fake response whose raise_for_status() is a no-op
    if kwargs.get("param") and kwargs.get("returnValue"):
        return mock_data(param=kwargs.get("param"), data=kwargs.get("data"))
    status, rule_out = mock_data(param=kwargs.get("param"), data=kwargs.get("data"))
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = rule_out
    fake_resp.text = str(rule_out)
    fake_resp.raise_for_status = MagicMock()  # <-- no exception
    return fake_resp

def mock_run_exception(*args, **kwargs):
    print("mock_run_exception")
    raise Exception("Unexpected exception found during execution: boom")

def mock_failed_request(*args, **kwargs):
    fake_resp = MagicMock()
    fake_resp.status_code = 400
    fake_resp.json.return_value = None
    fake_resp.text = str({})
    fake_resp.raise_for_status = MagicMock()  # <-- no exception
    return fake_resp

def mock_excep_request(*args, **kwargs):
    fake_resp = MagicMock()
    resp = requests.Response()
    resp.status_code = 404
    resp._content = b'{"errorMessage":"Error found"}'  # optional
    if kwargs.get('param') == 'HTTPError':
        if kwargs.get('flag') == 'AleadyExist':
            resp._content = b'{"errorMessage":"Add rule failed, Rule:ABC already exists."}'
            fake_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
                ERROR_400_MSG,
                response=resp
            )
        else:
            fake_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
                ERROR_400_MSG,
                response=resp
            )
    elif kwargs.get('param') == 'HTTPErrorWithoutResp':
        fake_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
            ERROR_404_MSG,
            response=None
        )
    elif kwargs.get('param') == 'RequestException':
        fake_resp.raise_for_status.side_effect = requests.exceptions.RequestException(
            ERROR_404_MSG,
            response=None
        )
        fake_resp.raise_for_status()
    elif kwargs.get('param') == 'RequestExceptionWithResp':
        fake_resp.raise_for_status.side_effect = requests.exceptions.RequestException(
            ERROR_400_MSG,
            response=resp
        )
    else:
        fake_resp.raise_for_status.side_effect = Exception(ERROR_500_MSG)

    fake_resp.return_value = fake_resp

    return fake_resp