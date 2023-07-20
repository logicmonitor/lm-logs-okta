import gzip
import logging
import pytest
import json
import requests
from unittest import mock



from oktalogcollector import log_ingester as li
from oktalogcollector import msgspec_okta_event as moe

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def test_no_auth_specified(mocker):
    with pytest.raises(ValueError):

        mocker.patch("oktalogcollector.aws.get_secret_val", return_value=None)
        log_ingester = li.LogIngester()
        

def test_partial_lmv1_specified_with_no_bearer(partial_lmv1_defined_with_no_bearer):
    with pytest.raises(ValueError):
        with mock.patch("oktalogcollector.aws.get_secret_val") as mck:
            mck.side_effect = partial_lmv1_defined_with_no_bearer
            log_ingester = li.LogIngester()
            


def test_only_lmv1_specified_with_no_bearer(mocker,get_secret_val_only_LMV1_defined, mock_log_ingest_post):
    with mock.patch("oktalogcollector.aws.get_secret_val") as mck:
        mck.side_effect = get_secret_val_only_LMV1_defined
        log_ingester = li.LogIngester()
        mocker.patch("time.time", return_value=123456789)
        raw_resp_from_okta = moe.loads(open("tests/data/resp.json").read())
        log_ingester.ingest_to_lm_logs(raw_resp_from_okta)
        auth = log_ingester.generate_auth("[]")
        assert "LMv1 some-string" in auth

def test_all_auth_specified(mocker,get_secret_val_all_defined, mock_log_ingest_post):
    with mock.patch("oktalogcollector.aws.get_secret_val") as mck:
        mck.side_effect = get_secret_val_all_defined
        log_ingester = li.LogIngester()
        mocker.patch("time.time", return_value=123456789)
        raw_resp_from_okta = moe.loads(open("tests/data/resp.json").read())
        log_ingester.ingest_to_lm_logs(raw_resp_from_okta)
        auth = log_ingester.generate_auth("[]")
        assert "LMv1 some-string" in auth

def test_only_bearer_specified(mocker,get_secret_only_bearer_specified, mock_log_ingest_post):
    with mock.patch("oktalogcollector.aws.get_secret_val") as mck:
        mck.side_effect = get_secret_only_bearer_specified
        log_ingester = li.LogIngester()
        mocker.patch("time.time", return_value=123456789)
        raw_resp_from_okta = moe.loads(open("tests/data/resp.json").read())
        log_ingester.ingest_to_lm_logs(raw_resp_from_okta)
        auth = log_ingester.generate_auth("[]")
        assert "Bearer some-string" in auth

def test_partial_lmv1_with_bearer_specified(mocker,get_secret_partial_lmv1_with_bearer_specified, mock_log_ingest_post):
    with mock.patch("oktalogcollector.aws.get_secret_val") as mck:
        mck.side_effect = get_secret_partial_lmv1_with_bearer_specified
        log_ingester = li.LogIngester()
        mocker.patch("time.time", return_value=123456789)
        raw_resp_from_okta = moe.loads(open("tests/data/resp.json").read())
        log_ingester.ingest_to_lm_logs(raw_resp_from_okta)
        auth = log_ingester.generate_auth("[]")
        assert "Bearer some-string" in auth



@pytest.fixture(name="partial_lmv1_defined_with_no_bearer", scope="session")
def fixture_mock_partial_lmv1_defined_with_no_bearer():
    def _get_secret_val1(key):
        returns = {
            "id" : "some-string",
            "key" : None,
            "token" : None
        }
        return returns[key]
    

    return _get_secret_val1
    
@pytest.fixture(name="get_secret_val_only_LMV1_defined", scope="session")
def fixture_mock_only_LMV1_defined():
    def _get_secret_val2(key):
        returns = {
            "id" : "some-string",
            "key" : "some-string",
            "token" : None
        }
        return returns[key]
    

    return _get_secret_val2

@pytest.fixture(name="get_secret_val_all_defined",scope="session")
def fixture_mock_all_auth_defined():
    def _get_secret_val3(key):
        returns = {
            "id" : "some-string",
            "key" : "some-string",
            "token" : "some-string"
        }
        return returns[key]
    

    return _get_secret_val3

@pytest.fixture(name="get_secret_only_bearer_specified",scope="session")
def fixture_mock_only_bearer_defined():
    def _get_secret_val3(key):
        returns = {
            "id" : None,
            "key" : None,
            "token" : "some-string"
        }
        return returns[key]
    

    return _get_secret_val3

@pytest.fixture(name="get_secret_partial_lmv1_with_bearer_specified",scope="session")
def fixture_mock_partial_lmv1_with_bearer_specified():
    def _get_secret_val3(key):
        returns = {
            "id" : "some-string",
            "key" : None,
            "token" : "some-string"
        }
        return returns[key]
    

    return _get_secret_val3

@pytest.fixture
def mock_log_ingest_post(
        requests_mock
):
    def matcher(req):
        if req.url != "https://mycompany.logicmonitor.com/rest/log/ingest":
            return None
        if json.load(open("tests/data/expected_lm_logs_payload_data.json")) == \
                json.loads(gzip.decompress(req.body).decode('utf-8')) \
                and (req.headers.get("Authorization") == \
                "LMv1 some-string:ZjU3NDkyZmZmZTQzOTgzMzVmOWZjMzNiOTQ4O" \
                "GI0YWQ1YzdiZTIwNGMyOGE5NTQ0ZjZjZDUwYzY1NzE0N2RmZQ==:123456789000" or req.headers.get("Authorization") == "Bearer some-string"):
            return create_successful_ingestion_response()
    requests_mock._adapter.add_matcher(matcher)
    yield
    
def create_successful_ingestion_response():
    resp = requests.Response()
    resp.status_code = 202
    resp.headers = {'x-request-id': '83f04eea-2d09-4dea-9bc5-1ae4793c6cdb'}
    resp._content = json.dumps({"success": True, "message": "Accepted"}).encode('utf-8')
    return resp