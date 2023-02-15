import gzip
import logging
import pytest
import json
import requests



from oktalogcollector import log_ingester as li
from oktalogcollector import msgspec_okta_event as moe

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def test_prepare_lm_log(mocker):
    mocker.patch("oktalogcollector.aws.get_secret_val", return_value="some-string")
    log_ingester = li.LogIngester()
    # sample okta event
    okta_event = moe.load_single_event(open("tests/data/sample_okta_event.json").read())
    prepared_event = log_ingester.prepare_lm_log_event(okta_event)
    logger.info(" built okta event : {0}".format(str(json.dumps(prepared_event))))
    expected_event = json.load(open("tests/data/expected_lm_log_event.json"))
    assert expected_event == prepared_event, "Should build lm-log event"


@pytest.fixture
def mock_log_ingest_post(
        requests_mock
):
    def matcher(req):
        if req.url != "https://mycompany.logicmonitor.com/rest/log/ingest":
            return None
        if json.load(open("tests/data/expected_lm_logs_payload_data.json")) == \
                json.loads(gzip.decompress(req.body).decode('utf-8')) \
                and req.headers.get("Authorization") == \
                "LMv1 some-string:MmM4MTk3YzQ0NmQ1M2FkZDBkNjBjZmJlZWYwZmQzZj" \
                "ZlMTY5NDgzNjU1NmUzZjU3OTYzMGIzNjAwMWY5NjdlMA==:123456789000":
            return create_successful_ingestion_response()
    requests_mock._adapter.add_matcher(matcher)
    yield


def test_lm_log_payload(mocker, requests_mock, mock_log_ingest_post):
    mocker.patch("oktalogcollector.aws.get_secret_val"
                 "", return_value="some-string")
    mocker.patch("time.time", return_value=123456789)
    raw_resp_from_okta = moe.loads(open("tests/data/resp.json").read())
    li.LogIngester().ingest_to_lm_logs(raw_resp_from_okta)


def create_successful_ingestion_response():
    resp = requests.Response()
    resp.status_code = 202
    resp.headers = {'x-request-id': '83f04eea-2d09-4dea-9bc5-1ae4793c6cdb'}
    resp._content = json.dumps({"success": True, "message": "Accepted"}).encode('utf-8')
    return resp
