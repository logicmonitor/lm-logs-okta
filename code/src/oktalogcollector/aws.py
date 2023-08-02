import boto3
import botocore
import botocore.session
from aws_secretsmanager_caching import SecretCache, SecretCacheConfig
from . import constants as const
from . import helper as hp
import logging

# aws secret cache
secret_client = botocore.session.get_session().create_client('secretsmanager')
secret_cache_config = SecretCacheConfig()
secret_cache = SecretCache(config=secret_cache_config, client=secret_client)

s3 = boto3.resource('s3')

BUCKET = hp.get_required_attr_from_env(const.BUCKET)


def get_secret_val(key):
    if len(key) > 0:
        return secret_cache.get_secret_string(key)
    else : 
        return None


def update_s3_obj(obj_key, body):

    if bucket_exists(BUCKET):
        try:
            s3.Object(BUCKET, obj_key) \
                .put(Body=body.encode(const.ENCODING))
            return True
        except botocore.exceptions.ClientError as e:
            raise Exception("Error while writing last report time to s3 bucket. error = " + str(e))
    else:
        raise Exception("S3 bucket not found bucket. Please create S3 bucket of a name=%s "
                        "or use corresponding valid env variables for persisting lastReportTime to continue,"
                        , BUCKET)


def bucket_exists(bucket):
    exists = True
    try:
        s3.meta.client.head_bucket(Bucket=bucket)
    except botocore.exceptions.ClientError as e:
        # If a client error is thrown, then check that it was a 404 error.
        # If it was a 404 error, then the bucket does not exist.
        error_code = e.response['Error']['Code']
        if error_code == '404':
            exists = False
        else:
            logging.error("S3 bucket not found bucket=%s, error=%s.", error_code)
            raise Exception("S3 bucket not found bucket. Please create S3 bucket of a name=%s "
                            "or use corresponding valid env variables for persisting lastReportTime to continue,"
                            , BUCKET)
    return exists


def get_s3_obj_str(obj_key):
    try:
        next_link_data = s3.Object(BUCKET, obj_key).get()['Body'].read().decode(const.ENCODING)
        return next_link_data
        # if validators.url(next_url):
        #     logging.info("next url found for polling in s3 = %s", next_url)
        #     return next_url
        # else:
        #     logging.warning("Persisted URL in s3 is not parsable or invalid. "
        #                     "This results in back-filling logs. URL=%s", next_url)
        #     return None

    except botocore.exceptions.ClientError as e:
        logging.error("Error while retrieving persisted url %s", str(e))
        if bucket_exists(BUCKET):
            logging.info("URL not found in s3 bucket. Back-filling logs. ")
            return None
        else:
            raise Exception("Unable to connect to S3 bucket %s. It does not exist. S3 bucket is required to persist "
                            "the last reported "
                            "timestamp. Exception=%s", BUCKET, e)
