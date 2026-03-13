from tests.constants import *
from unittest.mock import patch, MagicMock
import requests

def mock_read_file(*args, **kwargs):
    #print("mock_cert", args, kwargs)
    if args[0] in CERTIFICATES:
        return kwargs.get("cert")
    else:
        return kwargs.get("node")

def mock_request(*args, **kwargs):
    #print("Mocked request", args, kwargs)
    data = kwargs.get("cert") if kwargs.get("cert") else {}
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = data
    fake_resp.text = str(data)
    fake_resp.raise_for_status = MagicMock()  # <-- no exception
    return fake_resp

def mock_cert_exception(*args, **kwargs):
    print("mock_cert_exception")
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
    elif kwargs.get('param') == 'RequestExceptionWithResp':
        fake_resp.raise_for_status.side_effect = requests.exceptions.RequestException(
            ERROR_400_MSG,
            response=resp
        )
    else:
        fake_resp.raise_for_status.side_effect = Exception(ERROR_500_MSG)

    fake_resp.return_value = fake_resp

    return fake_resp