import requests
import json
import hashlib
import base64
import time
import hmac
import gzip
from . import aws
from . import constants as const
from . import helper as hp
from functools import reduce
import operator
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class LogIngester:

    def __init__(self):
        self.metadata_deep_path = None
        self.company = hp.get_required_attr_from_env(const.COMPANY_NAME)
        self.lm_access_id = aws.get_secret_val(hp.get_required_attr_from_env(const.LM_ACCESS_ID))
        self.lm_access_key = aws.get_secret_val(hp.get_required_attr_from_env(const.LM_ACCESS_KEY))
        self.lm_resource_id = hp.get_attr_as_json_from_env(const.LM_RESOURCE_ID)
        self.set_metadata_deep_path()
        self.include_metadata_keys = hp.get_required_attr_from_env(const.INCLUDE_METADATA_KEYS)
        self.service_name = hp.get_attr_from_env(const.LM_SERVICE_NAME_KEY)

    def set_metadata_deep_path(self):
        try:
            metadata_deep_path = []
            include_metadata_keys = hp.get_attr_from_env(const.INCLUDE_METADATA_KEYS).replace(' ', '')  # remove spaces
            for k in include_metadata_keys.split(','):
                metadata_deep_path.append(k.split('.'))
            self.metadata_deep_path = metadata_deep_path
        except Exception as e:
            logger.warning(e, exc_info=True)
            self.metadata_deep_path = None

    def get_company_name(self):
        return self.company

    def ingest_to_lm_logs(self, raw_json_resp):
        if len(raw_json_resp) < 1:
            return
        # split
        logger.info("number of logs in response = %s", str(len(raw_json_resp)))
        payload = []
        for event in raw_json_resp:
            lm_log_event = self.prepare_lm_log_event(event)
            if len((json.dumps(payload) + json.dumps(lm_log_event)).encode(const.ENCODING)) \
                    < const.MAX_ALLOWED_PAYLOAD_SIZE:
                payload.append(lm_log_event)
            else:
                self.report_logs(payload)
                logging.debug("resetting payload to empty")
                payload = []
        logger.info("payload size =" + str(len(json.dumps(payload).encode(const.ENCODING))))
        self.report_logs(payload)

    def prepare_lm_log_event(self, event):
        lm_log_event = {"message": json.dumps(event), "timestamp": event[const.OKTA_KEY_TIMESTAMP],
                        "_lm.logsource_type": "lm-logs-okta"}

        if self.service_name:
            lm_log_event[const.LM_KEY_SERVICE] = self.service_name
        if self.lm_resource_id:
            lm_log_event["_lm.resourceId"] = self.lm_resource_id

        if self.metadata_deep_path:
            for path in self.metadata_deep_path:
                try:
                    lm_log_event['.'.join(path)] = reduce(operator.getitem, path, event)
                except Exception as e:
                    logger.warning("Failed to add metadata {0} to lm-log event. Error = {1}".format(path, str(e)))

        return lm_log_event

    def report_logs(self, payload):
        resource_path = "/log/ingest"
        http_verb = 'POST'
        url = "https://" + self.company + ".logicmonitor.com/rest" + resource_path
        data = json.dumps(payload)
        logging.debug("Payload to ingest =%s", data)
        epoch = str(int(time.time() * 1000))
        request_vars = http_verb + epoch + data + resource_path
        signature = base64.b64encode(hmac.new(self.lm_access_key.encode(const.ENCODING),
                                              msg=request_vars.encode(const.ENCODING),
                                              digestmod=hashlib.sha256).hexdigest().encode(const.ENCODING))
        auth = 'LMv1 ' + self.lm_access_id + ':' + signature.decode() + ':' + epoch
        headers = {'Content-Encoding': 'gzip', 'Content-Type': 'application/json', 'Authorization': auth,
                   'User-Agent': 'Okta-log-lambda-function'}
        logger.debug("making post request.")
        response = requests.post(url, data=gzip.compress(data.encode(const.ENCODING)), headers=headers)
        if response.status_code == 202:
            logger.info("Successfully ingested events to log-ingest. x-request-id=%s response=%s",
                        response.headers['x-request-id'], response.json())
        elif response.status_code == 207:
            logger.debug("Partial events accepted by log-ingest. x-request-id=%s, response=%s",
                         response.headers['x-request-id'], response.json())
        else:
            logger.error("Log ingestion failed. error=%s", response.json())
            raise Exception("Error while ingesting logs. Stopping log-ingestion. Will attempt back-filling in "
                            "next lambda function execution..")
