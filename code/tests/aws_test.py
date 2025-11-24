import pytest
import logging
from unittest.mock import MagicMock, patch
import botocore
import oktalogcollector.aws as aws

logger = logging.getLogger()
logger.setLevel(logging.INFO)

@pytest.fixture(autouse=True)
def mock_env_and_bucket(monkeypatch):
    monkeypatch.setattr(aws.hp, "get_required_attr_from_env", lambda key: "test-bucket")
    aws.BUCKET = "test-bucket"


@pytest.fixture
def mock_s3_resource(mocker):
    s3_mock = mocker.patch("oktalogcollector.aws.s3")
    return s3_mock


@pytest.fixture
def mock_secret_cache(mocker):
    return mocker.patch.object(aws, "secret_cache")


def test_get_secret_val_with_key(mock_secret_cache):
    mock_secret_cache.get_secret_string.return_value = "secret-value"
    result = aws.get_secret_val("my-secret-key")
    assert result == "secret-value"
    mock_secret_cache.get_secret_string.assert_called_once_with("my-secret-key")


def test_get_secret_val_with_empty_key(mock_secret_cache):
    result = aws.get_secret_val("")
    assert result is None
    mock_secret_cache.get_secret_string.assert_not_called()


def test_update_s3_obj_success(mock_s3_resource, mocker):
    mock_s3_resource.Object.return_value.put.return_value = True
    mocker.patch("oktalogcollector.aws.bucket_exists", return_value=True)

    result = aws.update_s3_obj("some-key", "my-body")
    assert result is True
    mock_s3_resource.Object.return_value.put.assert_called_once()


def test_update_s3_obj_s3_write_failure(mock_s3_resource, mocker):
    mocker.patch("oktalogcollector.aws.bucket_exists", return_value=True)
    mock_s3_resource.Object.return_value.put.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "500"}}, "PutObject"
    )

    with pytest.raises(Exception, match="Error while writing last report time to s3 bucket"):
        aws.update_s3_obj("some-key", "my-body")


def test_bucket_exists_true(mock_s3_resource):
    mock_s3_resource.meta.client.head_bucket.return_value = {}
    assert aws.bucket_exists("test-bucket") is True


def test_bucket_exists_false(mock_s3_resource):
    mock_s3_resource.meta.client.head_bucket.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "404"}}, "HeadBucket"
    )
    assert aws.bucket_exists("test-bucket") is False

def test_get_s3_obj_str_success(mock_s3_resource):
    mock_body = MagicMock()
    mock_body.read.return_value = b'some-data'
    mock_s3_resource.Object.return_value.get.return_value = {'Body': mock_body}

    result = aws.get_s3_obj_str("test-key")
    assert result == 'some-data'


def test_get_s3_obj_str_not_found_returns_none(mock_s3_resource, mocker):
    mock_s3_resource.Object.return_value.get.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchKey"}}, "GetObject"
    )
    mocker.patch("oktalogcollector.aws.bucket_exists", return_value=True)

    result = aws.get_s3_obj_str("test-key")
    assert result is None


def test_get_s3_obj_str_bucket_missing_raises(mock_s3_resource, mocker):
    mock_s3_resource.Object.return_value.get.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDenied"}}, "GetObject"
    )
    mocker.patch("oktalogcollector.aws.bucket_exists", return_value=False)

    with pytest.raises(Exception, match="Unable to connect to S3 bucket"):
        aws.get_s3_obj_str("test-key")