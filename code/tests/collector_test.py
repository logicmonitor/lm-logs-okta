import pytest
import logging
from oktalogcollector.collector import lambda_handler
from oktalogcollector.okta_log_collector import OktaLogCollector

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class MockContext:
  def __init__(self):
    self.log_stream_name = "test_log_stream"
    self.log_group_name = "test_log_group"
    self.aws_request_id = "test_request_id"
    self.memory_limit_in_mb = 128

  def get_remaining_time_in_millis(self):
    return 5000


@pytest.fixture()
def mock_okta_log_collector_success(mocker):
  mocker.patch.object(OktaLogCollector, "collect_logs", return_value=None)
  yield


@pytest.fixture()
def mock_okta_log_collector_failure(mocker):
  mocker.patch.object(OktaLogCollector, "collect_logs", side_effect=Exception("Boom!"))
  yield

@pytest.fixture
def mock_okta_log_collector_success():
    with patch("oktalogcollector.log_ingester.run") as mock_run:
        mock_run.return_value = {
            "status": "SUCCESS",
            "details": "Successfully executed the function"
        }
        yield mock_run
