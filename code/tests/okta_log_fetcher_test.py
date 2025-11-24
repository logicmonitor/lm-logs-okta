import unittest
import os
import json
import logging
from unittest import mock
from datetime import datetime, timezone, timedelta
import botocore.exceptions

# Set a default value for LM_RESOURCE_ID BEFORE the module import
# This prevents a TypeError during test collection, as the module-level
# json.loads() in okta_log_fetcher.py runs before setUp()
os.environ["LM_RESOURCE_ID"] = "{}"

from oktalogcollector import okta_log_fetcher as okta_log_fetcher

logging.disable(logging.CRITICAL)


class TestOktaLogFetcher(unittest.TestCase):

  def setUp(self):
    """Set up mock environment variables and patch external dependencies."""
    self.mock_env = {
      "LRT_S3_BUCKET": "test-bucket",
      "LRT_S3_REGION": "us-east-1",
      "MAX_BACK_FILL_DURATION_MIN": "60",
      "OKTA_DOMAIN": "test.okta.com",
      "OKTA_API_KEY": "okta_api_key_secret_name",
      "OKTA_EVENT_FILTER": "eventType eq \"user.session.start\"",
      "OKTA_EVENT_KEYWORD": "admin",
      "COMPANY_NAME": "test-company",
      "LM_ACCESS_ID": "lm_access_id_secret_name",
      "LM_ACCESS_KEY": "lm_access_key_secret_name",
      "LM_RESOURCE_ID": "{\"system.hostname\": \"okta\"}",
      "INCLUDE_METADATA_KEYS": "actor,client,outcome",
      "OKTA_SINCE_TIME_OFFSET_MILLI": "1000",
    }

    self.env_patcher = mock.patch.dict('os.environ', self.mock_env)
    self.env_patcher.start()

    # Reload okta_log_fetcher to make it use the mocked os.environ values
    self.mock_max_payload = mock.patch('oktalogcollector.okta_log_fetcher.MAX_ALLOWED_PAYLOAD_SIZE', 500)
    self.mock_max_payload.start()

    # Patch all external dependencies
    self.mock_boto3 = mock.patch('oktalogcollector.okta_log_fetcher.boto3').start()
    self.mock_s3 = mock.patch('oktalogcollector.okta_log_fetcher.s3').start()
    self.mock_requests = mock.patch('oktalogcollector.okta_log_fetcher.requests').start()
    self.mock_secret_cache = mock.patch('oktalogcollector.okta_log_fetcher.secret_cache').start()
    self.mock_validators = mock.patch('oktalogcollector.okta_log_fetcher.validators').start()
    self.mock_logging = mock.patch('oktalogcollector.okta_log_fetcher.logging').start()
    self.mock_datetime = mock.patch('oktalogcollector.okta_log_fetcher.datetime').start()
    self.mock_time = mock.patch('oktalogcollector.okta_log_fetcher.time').start()
    self.mock_dp = mock.patch('oktalogcollector.okta_log_fetcher.dp').start()

    # Configure default mock behaviors
    self.mock_validators.url.return_value = True
    self.mock_secret_cache.get_secret_string.side_effect = self.mock_get_secret
    self.mock_time.time.return_value = 1234567.890

    # Mock datetime.now()
    self.fixed_now = datetime(2023, 10, 27, 12, 0, 0, tzinfo=timezone.utc)
    self.mock_datetime.now.return_value = self.fixed_now
    self.mock_datetime.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)

    # Mock S3 resource
    self.mock_s3_object = mock.Mock()
    self.mock_s3.Object.return_value = self.mock_s3_object
    self.mock_s3.meta.client.head_bucket.return_value = True

    # Mock requests Response
    self.mock_response = mock.Mock()
    self.mock_requests.request.return_value = self.mock_response
    self.mock_requests.post.return_value = self.mock_response

    # Store env vars for easy access
    self.company_name = self.mock_env["COMPANY_NAME"]
    self.okta_domain = self.mock_env["OKTA_DOMAIN"]

  def tearDown(self):
    """Stop all patchers."""
    self.env_patcher.stop()
    self.mock_max_payload.stop()
    mock.patch.stopall()

  def mock_get_secret(self, secret_name):
    """Simulate fetching secrets from Secrets Manager."""
    if secret_name == "okta_api_key_secret_name":
      return "fake-okta-api-key"
    if secret_name == "lm_access_id_secret_name":
      return "fake-lm-access-id"
    if secret_name == "lm_access_key_secret_name":
      return "fake-lm-access-key"
    return "unknown-secret"

  def test_bucket_exists_true(self):
    self.mock_s3.meta.client.head_bucket.return_value = True
    self.assertTrue(okta_log_fetcher.bucket_exists(self.mock_env["LRT_S3_BUCKET"]))

  def test_bucket_exists_false_404(self):
    self.mock_s3.meta.client.head_bucket.side_effect = botocore.exceptions.ClientError(
      {'Error': {'Code': '404'}}, 'HeadBucket'
    )
    self.assertFalse(okta_log_fetcher.bucket_exists(self.mock_env["LRT_S3_BUCKET"]))

  def test_bucket_exists_other_error(self):
    self.mock_s3.meta.client.head_bucket.side_effect = botocore.exceptions.ClientError(
      {'Error': {'Code': '500'}}, 'HeadBucket'
    )
    with self.assertRaises(Exception) as context:
      okta_log_fetcher.bucket_exists(self.mock_env["LRT_S3_BUCKET"])
    self.assertIn("S3 bucket not found bucket", str(context.exception))


  def test_get_last_report_time(self):
    # This function is simplified in the user's code, the S3 part is commented out.
    # We test the active part.
    expected_time = self.fixed_now - timedelta(minutes=int(self.mock_env["MAX_BACK_FILL_DURATION_MIN"]))
    self.assertEqual(okta_log_fetcher.get_last_report_time(), expected_time)

  def test_set_last_report_time_bucket_not_exists(self):
    okta_log_fetcher.bucket_exists = mock.Mock(return_value=False)
    with self.assertRaises(Exception) as context:
      okta_log_fetcher.set_last_report_time("timestamp")
    self.assertIn("S3 bucket not found bucket", str(context.exception))

  def test_set_last_report_time_s3_put_error(self):
    okta_log_fetcher.bucket_exists = mock.Mock(return_value=True)
    self.mock_s3_object.put.side_effect = botocore.exceptions.ClientError(
      {'Error': {'Code': 'AccessDenied'}}, 'PutObject'
    )
    with self.assertRaises(Exception) as context:
      okta_log_fetcher.set_last_report_time("timestamp")
    self.assertIn("Error while writing last report time", str(context.exception))

  def test_build_log_fetching_url_no_optional_params(self):
    # Test without filter/keyword
    self.env_patcher.stop()
    minimal_env = self.mock_env.copy()
    minimal_env["OKTA_EVENT_FILTER"] = ""
    minimal_env["OKTA_EVENT_KEYWORD"] = ""
    self.env_patcher = mock.patch.dict('os.environ', minimal_env, clear=True)
    self.env_patcher.start()

    mock_time = self.fixed_now - timedelta(minutes=int(self.mock_env["MAX_BACK_FILL_DURATION_MIN"]))
    mock_iso_time = mock_time.isoformat().replace("+00:00", 'Z')
    okta_log_fetcher.get_last_report_time = mock.Mock(return_value=mock_time)

    url = okta_log_fetcher.build_log_fetching_url()
    self.assertNotIn("&filter=", url)
    self.assertNotIn("&q=", url)
    self.env_patcher.stop()
    self.env_patcher = mock.patch.dict('os.environ', self.mock_env, clear=True) # restore
    self.env_patcher.start()

  def test_ingest_to_lm_logs_empty(self):
    okta_log_fetcher.report_logs = mock.Mock()
    okta_log_fetcher.ingest_to_lm_logs([])
    okta_log_fetcher.report_logs.assert_not_called()

  def test_fetch_logs_pagination_empty_response(self):
    start_url = "http://start.url"
    next_url_1 = "http://next.url.1"
    self_url = "http://self.url"

    okta_log_fetcher.get_next_fetching_url = mock.Mock(return_value=start_url)
    okta_log_fetcher.ingest_to_lm_logs = mock.Mock()
    okta_log_fetcher.update_next_fetch_url_in_s3 = mock.Mock()

    # Mock requests.request to handle pagination
    mock_resp_1 = mock.Mock(
      links={"next": {"url": next_url_1}, "self": {"url": self_url}},
      json=mock.Mock(return_value=[{"log": "1"}])
    )
    mock_resp_2 = mock.Mock(
      links={"next": {"url": "foo"}, "self": {"url": self_url}}, # "next" URL will be used
      json=mock.Mock(return_value=[]) # Empty list stops loop
    )

    self.mock_requests.request.side_effect = [mock_resp_1, mock_resp_2]

    okta_log_fetcher.fetch_logs()

    self.assertEqual(self.mock_requests.request.call_count, 2)
    self.assertEqual(okta_log_fetcher.ingest_to_lm_logs.call_count, 1) # only first call
    okta_log_fetcher.ingest_to_lm_logs.assert_any_call([{"log": "1"}])

    okta_log_fetcher.update_next_fetch_url_in_s3.assert_called_with(self_url)

if __name__ == '__main__':
  unittest.main(argv=['first-arg-is-ignored'], exit=False)