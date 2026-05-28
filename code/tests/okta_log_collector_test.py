import gzip
import pytest
import json
import requests
import logging
from unittest import mock
from datetime import datetime, timezone, timedelta
from oktalogcollector import log_ingester as li
from oktalogcollector import msgspec_okta_event as moe
from oktalogcollector.okta_log_collector import OktaLogCollector, MAX_RETRIES

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


@pytest.fixture
def mock_env(mocker):
  """Mocks required environment variables."""
  mocker.patch.dict('os.environ', {
    "OKTA_DOMAIN": "somedomain.com",
    "OKTA_API_KEY": "secret-key-name"
  })

@pytest.mark.usefixtures("mock_env")
class TestOktaLogCollector:

  @pytest.fixture(autouse=True)
  def setup(self, mocker):
    """Setup for each test method."""
    self.mock_log_ingester = mock.MagicMock()
    mocker.patch("oktalogcollector.log_ingester.LogIngester", return_value=self.mock_log_ingester)
    self.mock_log_ingester.get_company_name.return_value = "test-company"

    self.mock_validators = mocker.patch("oktalogcollector.okta_log_collector.validators")
    self.mock_aws_secret = mocker.patch("oktalogcollector.aws.get_secret_val",
                                        return_value="super-secret-api-key")
    self.mock_aws_s3_get = mocker.patch("oktalogcollector.aws.get_s3_obj_str", return_value=None)
    self.mock_aws_s3_update = mocker.patch("oktalogcollector.aws.update_s3_obj")
    self.mock_requests = mocker.patch("oktalogcollector.okta_log_collector.requests")
    self.mock_msgspec = mocker.patch("oktalogcollector.okta_log_collector.msgspec_okta_event")
    self.mock_datetime = mocker.patch("oktalogcollector.okta_log_collector.datetime", wraps=datetime)

    # Fix datetime.now() to a predictable value
    self.mock_now = datetime(2025, 1, 1, 12, 2, 0, tzinfo=timezone.utc)
    self.mock_datetime.now.return_value = self.mock_now

    self.collector = OktaLogCollector()

  def test_get_domain(self):
    assert self.collector.get_domain() == "somedomain.com"

  def test_get_last_report_time(self):
    expected_time = self.mock_now - timedelta(minutes=2)
    assert self.collector.get_last_report_time() == expected_time

  def test_get_next_link_s3_obj_key(self):
    assert self.collector.get_next_link_s3_obj_key() == "nextLinkForOktaLogs-mycompany-somedomain.com"

  def test_build_log_fetching_url(self):
    expected_url = "https://somedomain.com/api/v1/logs?since=2025-01-01T12:00:00Z&sortOrder=ASCENDING&limit=1000"
    assert self.collector.build_log_fetching_url() == expected_url

  def test_update_next_url_to_query_invalid_url(self):
    self.mock_validators.url.return_value = False
    self.collector.update_next_url_to_query("not-a-url", 0)
    self.mock_aws_s3_update.assert_not_called()

  def test_update_next_url_to_query_invalid_retry(self):
    self.mock_validators.url.return_value = True
    self.collector.update_next_url_to_query("http://valid.url", -1)
    self.mock_aws_s3_update.assert_not_called()

  def test_get_url_to_query_no_s3_object(self):
    self.mock_aws_s3_get.return_value = None
    expected_url = "https://somedomain.com/api/v1/logs?since=2025-01-01T12:00:00Z&sortOrder=ASCENDING&limit=1000"
    assert self.collector.get_url_to_query() == expected_url

  def test_get_url_to_query_s3_object_valid(self):
    s3_url = "http://s3.saved.url"
    s3_data = json.dumps({"okta_next_link": s3_url, "next_link_retries": 1})
    self.mock_aws_s3_get.return_value = s3_data
    self.mock_validators.url.return_value = True

    assert self.collector.get_url_to_query() == s3_url
    assert self.collector.retry_attempt == 1

  def test_get_url_to_query_s3_object_invalid_url(self):
    s3_data = json.dumps({"okta_next_link": "not-a-url", "next_link_retries": 1})
    self.mock_aws_s3_get.return_value = s3_data
    self.mock_validators.url.return_value = False

    expected_url = "https://somedomain.com/api/v1/logs?since=2025-01-01T12:00:00Z&sortOrder=ASCENDING&limit=1000"
    assert self.collector.get_url_to_query() == expected_url

  def test_get_url_to_query_s3_object_max_retries(self):
    s3_url = "http://s3.saved.url"
    s3_data = json.dumps({"okta_next_link": s3_url, "next_link_retries": MAX_RETRIES})
    self.mock_aws_s3_get.return_value = s3_data
    self.mock_validators.url.return_value = True

    expected_url = "https://somedomain.com/api/v1/logs?since=2025-01-01T12:00:00Z&sortOrder=ASCENDING&limit=1000"
    assert self.collector.get_url_to_query() == expected_url

  def test_get_url_to_query_s3_object_json_error(self):
    self.mock_aws_s3_get.return_value = "invalid-json"
    with pytest.raises(json.JSONDecodeError):
      self.collector.get_url_to_query()

  def test_collect_logs_http_error_first_request(self):
    # Start with S3 URL
    s3_url = "http://s3.saved.url"
    s3_data = json.dumps({"okta_next_link": s3_url, "next_link_retries": 1})
    self.mock_aws_s3_get.return_value = s3_data
    self.mock_validators.url.return_value = True

    # Mock request failure
    self.mock_requests.request.side_effect = requests.exceptions.HTTPError("401 Client Error")

    self.collector.collect_logs()

    # Check that no logs were ingested
    self.mock_log_ingester.ingest_to_lm_logs.assert_not_called()

    # Check that retry count was incremented and saved
    assert self.collector.retry_attempt == 2
    self.mock_aws_s3_update.assert_called_once_with(
      mock.ANY, json.dumps({"okta_next_link": s3_url, "next_link_retries": 2})
    )
