import requests
import json
import hashlib
import base64
import time
import hmac
import boto3
import botocore
import botocore.session
import validators
from aws_secretsmanager_caching import SecretCache, SecretCacheConfig
import os
from datetime import datetime, timedelta, timezone
from functools import reduce  # forward compatibility for Python 3
import operator
import dateutil.parser as dp
import logging

# last report time persistence config
BUCKET = os.environ.get("LRT_S3_BUCKET")
BUCKET_REGION = os.environ.get("LRT_S3_REGION")
MAX_BACK_FILL_DURATION_MIN = int(os.environ.get("MAX_BACK_FILL_DURATION_MIN"))

# config for okta log collection
OKTA_DOMAIN = os.environ.get("OKTA_DOMAIN")
OKTA_API_KEY = os.environ.get("OKTA_API_KEY")
OKTA_EVENT_FILTER = os.environ.get("OKTA_EVENT_FILTER")
OKTA_EVENT_KEYWORD = os.environ.get("OKTA_EVENT_KEYWORD")

# config for log-ingestion
COMPANY_NAME = os.environ.get("COMPANY_NAME")
LM_ACCESS_ID = os.environ.get("LM_ACCESS_ID")
LM_ACCESS_KEY = os.environ.get("LM_ACCESS_KEY")
LM_RESOURCE_ID = json.loads(os.environ.get("LM_RESOURCE_ID"))
INCLUDE_METADATA_KEYS = os.environ.get("INCLUDE_METADATA_KEYS")

# constants
OKTA_LOGS_ENDPOINT = "/api/v1/logs"
HTTP_PROTOCOL = "https://"
OKTA_KEY_MSG = "displayMessage"
OKTA_KEY_TIMESTAMP = "published"
LM_KEY_SERVICE = "resource.service.name"
LM_KEY_NAMESPACE = "resource.service.namespace"
MAX_ALLOWED_PAYLOAD_SIZE = 8 * 1024 * 1024 / 8  # we can compare len of string instead of

# okta shenanigans
"""
    okta system logs api(stable) has a bug of giving older logs despite of newer 'since' param
    defined in the query. Another bug observed is : Even if we specify sorting order in query,
    logs received in response appear to be out of order. 
    Will keep an eye on the ticket created :  
    https://support.okta.com/help/s/question/0D54z00008VsSACCA3/okta-system-log-api-returns-duplicate-events-and-older-than-since-query-param-specified-in-request?language=en_US
    
    OKTA_SINCE_TIME_OFFSET_MILLI is duration in milliseconds we add to persisted lastReportTime from s3, 
    so we query from since = persisted_time + offset
    
"""
OKTA_SINCE_TIME_OFFSET_MILLI = os.environ.get("OKTA_SINCE_TIME_OFFSET_MILLI")

# s3 for persisting last report time
s3 = boto3.resource('s3')

# secret cache
secret_client = botocore.session.get_session().create_client('secretsmanager')
secret_cache_config = SecretCacheConfig()
secret_cache = SecretCache(config=secret_cache_config, client=secret_client)


def fetch_logs():
    """"""

    # base_url = HTTP_PROTOCOL + OKTA_DOMAIN + OKTA_LOGS_ENDPOINT
    # last_report_time = get_last_report_time().isoformat().replace("+00:00", 'Z')
    # logging.info("LastReportTimeStamp being used as since = %s ", last_report_time)
    # query_param = "?since=" + last_report_time + "&sortOrder=ASCENDING" + "&limit=1000"
    #
    # if OKTA_EVENT_FILTER:
    #     query_param += "&filter=" + OKTA_EVENT_FILTER
    # if OKTA_EVENT_KEYWORD:
    #     query_param += "&q=" + OKTA_EVENT_KEYWORD
    #
    # final_url = get_next_fetching_url()
    url_for_fetching = get_next_fetching_url()
    logging.info("Using url to query logs at execution : %s", url_for_fetching)
    url_to_persist = url_for_fetching
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'SSWS {}'.format(secret_cache.get_secret_string(OKTA_API_KEY))
    }
    try:
        response = requests.request("GET", url_for_fetching, headers=headers)
        ingest_to_lm_logs(response.json())
        while response.links["next"]["url"]:
            logging.info("next url : %s ", response.links["next"]["url"])
            response = requests.request("GET", response.links["next"]["url"], headers=headers)
            if len(response.json()) < 1:
                logging.info("Reached last next link as no logs found this time. Stopping log collection.. ")
                # url_to_persist = response.links["next"]["url"]
                break
            else:
                ingest_to_lm_logs(response.json())
        logging.info("URL for fetching first : %s, url to persist at the ending : %s", url_for_fetching, url_to_persist)
        url_to_persist = response.links["self"]["url"]


    except Exception as e:
        logging.error(e, exc_info=True)
        raise Exception('Error occurred during execution')
    finally:
        if url_to_persist == url_for_fetching:
            logging.info("URL unchanged. Skipping update in s3.")
        else:
            logging.info("Updating next url in s3 to %s", url_to_persist)
            update_next_fetch_url_in_s3(url_to_persist)
        logging.info("Execution finished ... ")


def get_next_fetching_url():
    try:
        next_url = s3.Object(BUCKET, get_next_link_key()).get()['Body'].read().decode('utf-8')
        if validators.url(next_url):
            logging.info("next url found for polling in s3 = %s", next_url)
            return next_url
        else:
            logging.warning("Persisted URL in s3 is not parsable or invalid. "
                            "This results in back-filling logs. URL=%s", next_url)
            return build_log_fetching_url()

    except botocore.exceptions.ClientError as e:
        logging.error("Error while retrieving persisted url %s", str(e))
        if bucket_exists(BUCKET):
            logging.info("URL not found in s3 bucket. Back-filling logs. ")
            return build_log_fetching_url()
        else:
            raise Exception("Unable to connect to S3 bucket %s. It does not exist. S3 bucket is required to persist "
                            "the last reported "
                            "timestamp. Exception=%s", BUCKET, e)


def build_log_fetching_url():
    base_url = HTTP_PROTOCOL + OKTA_DOMAIN + OKTA_LOGS_ENDPOINT
    last_report_time = get_last_report_time().isoformat().replace("+00:00", 'Z')
    logging.info("LastReportTimeStamp being used as since = %s ", last_report_time)
    query_param = "?since=" + last_report_time + "&sortOrder=ASCENDING" + "&limit=1000"
    if OKTA_EVENT_FILTER:
        query_param += "&filter=" + OKTA_EVENT_FILTER
    if OKTA_EVENT_KEYWORD:
        query_param += "&q=" + OKTA_EVENT_KEYWORD
    final_url = base_url + query_param
    return final_url


def get_last_report_time():
    return datetime.now(timezone.utc) - timedelta(minutes=int(MAX_BACK_FILL_DURATION_MIN))
    # try:
    #     persisted_last_report_time = dp.isoparse(s3.Object(BUCKET, get_last_report_time_s3_object_key())
    #                                              .get()['Body'].read().decode('utf-8'))
    #     if OKTA_SINCE_TIME_OFFSET_MILLI and OKTA_SINCE_TIME_OFFSET_MILLI.isnumeric():
    #         persisted_last_report_time = persisted_last_report_time + \
    #                                      timedelta(milliseconds=int(OKTA_SINCE_TIME_OFFSET_MILLI))
    #
    #     logging.info("default_last_report_time = %s", str(default_last_report_time))
    #     return max(persisted_last_report_time, default_last_report_time)
    #
    # except botocore.exceptions.ClientError as e:
    #     logging.debug("Oops can not get s3 obj.. ")
    #     if bucket_exists(BUCKET):
    #         logging.debug("Last reportTime file does not exist in the bucket")
    #         return default_last_report_time
    #     else:
    #         raise Exception("Unable to connect to S3 bucket %s. It does not exist. S3 bucket is required to persist "
    #                         "the last reported "
    #                         "timestamp. Exception=%s", BUCKET, e)
    #
    # except ValueError:
    #     logging.warning("invalid timestamp read")
    #     return default_last_report_time


def update_next_fetch_url_in_s3(url):
    if validators.url(url):
        if bucket_exists(BUCKET):
            try:
                s3.Object(BUCKET, get_next_link_key()) \
                    .put(Body=url.encode('utf-8'))
                return True
            except botocore.exceptions.ClientError as e:
                # If a client error is thrown, then check that it was a 404 error.
                # If it was a 404 error, then the bucket does not exist.
                error_code = e.response['Error']['Code']
                # log
                raise Exception("Error while writing last report time to s3 bucket. error = " + str(e))
        else:
            raise Exception("S3 bucket not found bucket. Please create S3 bucket of a name=%s "
                            "or use corresponding valid env variables for persisting lastReportTime to continue,"
                            , BUCKET)
    else:
        logging.warning("Invalid URL. Not updating in s3.")


def set_last_report_time(timestamp):
    if bucket_exists(BUCKET):
        try:
            s3.Object(BUCKET, get_last_report_time_s3_object_key()) \
                .put(Body=timestamp.encode('utf-8'))
            return True
        except botocore.exceptions.ClientError as e:
            # If a client error is thrown, then check that it was a 404 error.
            # If it was a 404 error, then the bucket does not exist.
            error_code = e.response['Error']['Code']
            # log
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


def get_last_report_time_s3_object_key():
    return "lastReportTimeForOktaSystemLogs-" + COMPANY_NAME + "-" + OKTA_DOMAIN


def get_next_link_key():
    return "nextLinkForOktaLogs-" + COMPANY_NAME + "-" + OKTA_DOMAIN


def ingest_to_lm_logs(raw_json_resp):
    if len(raw_json_resp) < 1:
        return
    # split
    logging.info("number of logs in response = %s", str(len(raw_json_resp)))
    payload = []
    for event in raw_json_resp:
        lm_log_event = prepare_lm_log_event(event)
        if len(json.dumps(payload) + json.dumps(lm_log_event)) < MAX_ALLOWED_PAYLOAD_SIZE:
            payload.append(lm_log_event)
        else:
            report_logs(payload)
            logging.debug("resetting payload to empty")
            payload = []
    logging.info("payload size =" + str(len(json.dumps(payload).encode('utf-8'))))
    report_logs(payload)


def prepare_lm_log_event(event):
    lm_log_event = {"message": json.dumps(event), "timestamp": event[OKTA_KEY_TIMESTAMP],
                    LM_KEY_SERVICE: 'OKTA-system-logs'}
    if LM_RESOURCE_ID:
        lm_log_event["_lm.resourceId"] = LM_RESOURCE_ID
    for k in str(INCLUDE_METADATA_KEYS).split(','):

        # adding metadata
        if k in event:
            lm_log_event[k] = event[k]

    return lm_log_event


def report_logs(payload):
    resource_path = "/log/ingest"
    http_verb = 'POST'
    url = "https://" + COMPANY_NAME + ".logicmonitor.com/rest" + resource_path
    data = json.dumps(payload)
    logging.debug("Payload to ingest =%s", data)
    epoch = str(int(time.time() * 1000))
    request_vars = http_verb + epoch + data + resource_path
    signature = base64.b64encode(hmac.new(secret_cache.get_secret_string(LM_ACCESS_KEY).encode('utf-8'),
                                          msg=request_vars.encode('utf-8'),
                                          digestmod=hashlib.sha256).hexdigest().encode('utf-8'))
    auth = 'LMv1 ' + secret_cache.get_secret_string(LM_ACCESS_ID) + ':' + signature.decode() + ':' + epoch
    headers = {'Content-Type': 'application/json', 'Authorization': auth, 'User-Agent': 'Okta-log-lambda-function'}
    logging.debug("making post request.")
    response = requests.post(url, data=data, headers=headers)

    if response.status_code == 202:
        logging.info("Successfully ingested events to log-ingest. x-request-id=%s response=%s",
                     response.headers['x-request-id'], response.json())
    elif response.status_code == 207:
        logging.debug("Partial events accepted by log-ingest. x-request-id=%s, response=%s",
                      response.headers['x-request-id'], response.json())
    else:
        logging.error("Log ingestion failed. error=%s", response.json())
        raise Exception("Error while ingesting logs. Stopping log-ingestion. Will attempt back-filling in "
                        "next lambda function execution..")
    # logging.info("Attempting to update lastReportTime in S3")
    # update last report time
    # if len(payload) > 0:
    #     # as events are sorted according to timestamp
    #     #set_last_report_time(payload[-1]['timestamp'])
