import os
import json
from tests.constants import *
from unittest.mock import patch, MagicMock

def read_test_data(data_type=None):
    if data_type:
        with open(os.path.join(os.path.dirname(__file__)+TEST_DATA_PATH, data_type+".json")) as f:
            data_list = f.read()
    else:
        data_list = {}
    return json.loads(data_list)

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