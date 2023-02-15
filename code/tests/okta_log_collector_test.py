import gzip
import pytest
import json
import requests
import logging

from oktalogcollector import log_ingester as li
from oktalogcollector import msgspec_okta_event as moe

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def test_persist_url_on_successful_ingestion(mock_log_ingester):
    log_ingester = li.LogIngester()
    okta_event = moe.load_single_event(open("tests/data/sample_okta_event.json").read())
    prepared_event = log_ingester.prepare_lm_log_event(okta_event)
    expected_event = json.load(open("tests/data/expected_lm_log_event.json"))
    assert expected_event == prepared_event, "Should build lm-log event"


@pytest.fixture
def mock_log_ingest_post(
        requests_mock
):
    def matcher(req):
        if req.url != "https://mycompany.logicmonitor.com/rest/log/ingest":
            return None
        logger.info("lmv1 token = {0}".format(req.headers.get("Authorization")))
        if json.load(open("tests/data/expected_lm_logs_payload_data.json")) == \
                json.loads(gzip.decompress(req.body).decode('utf-8')) \
                and req.headers.get("Authorization") == \
                "LMv1 some-string:ZTY4MmY5ZGMwMzM2MGE1N2Y1ZjA0Mjg0MjFmYzg0ZmRjNGQ3" \
                "ZGZjZWQwMGQ1NWM2NTU5NzA3ODljZjczMDg5Yw==:123456789000":
            return create_successful_ingestion_response()
    requests_mock._adapter.add_matcher(matcher)
    yield


@pytest.fixture()
def mock_log_ingester(mocker):
    mocker.patch("oktalogcollector.aws.get_secret_val", return_value="some-string")
    mocker.patch("oktalogcollector.log_ingester.LogIngester.get_company_name", return_value="mycompany")
    mocker.patch("oktalogcollector.log_ingester.LogIngester.ingest_to_lm_logs")

@pytest.fixture()
def mock_okta_log_collection(requests_mock, mocker):
    mocker.patch("oktalogcollector.aws.get_secret_val", return_value="some-string")
    mocker.patch("oktalogcollector.log_ingester.LogIngester.get_company_name", return_value="mycompany")
    mocker.patch("oktalogcollector.log_ingester.LogIngester.ingest_to_lm_logs")
    def matcher(req):
        if req.method == "GET" and req.url == "https://somedomain.com/some_link_read_from_s3" and req.headers.get("Authorization") == 'SSWS key':
            resp = requests.Response()
            resp.status_code = 200
            resp.headers = {'x-request-id': '83f04eea-2d09-4dea-9bc5-1ae4793c6cdb'}
            resp._content = json.dumps({"success": True, "message": "Accepted"}).encode('utf-8')
    requests_mock._adapter.add_matcher(matcher)
    yield

@pytest.fixture()
def mock_aws_read_link(mocker):
    mocker.patch("oktalogcollector.aws.get_secret_val", return_value="some-string")
    mocker.patch("oktalogcollector.aws.get_s3_obj_str", return_value=json.dumps({'okta_next_link':'https://somedomain.com/some_link_read_from_s3', 'next_link_retries' : 1}))

