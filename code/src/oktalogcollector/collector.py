import logging
from .okta_log_collector import OktaLogCollector

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    try:
        logger.info('Starting okta log collection')

        logger.info('Event: {}'.format(event))
        logger.info("Log stream name: %s", str(context.log_stream_name))
        logger.info("Log group name: %s", str(context.log_group_name))
        logger.info("Request ID: %s", str(context.aws_request_id))
        logger.info("Mem. limits(MB) : %s", str(context.memory_limit_in_mb))
        # collect and ingest okta logs
        OktaLogCollector().collect_logs()
        logger.info('Execution of function completed')
        logger.info("Time remaining (MS): %s", str(context.get_remaining_time_in_millis()))
        return {
            "status": "SUCCESS",
            "details": "Successfully executed the function. "
        }
    except Exception as e:
        logger.error(e, exc_info=True)
        return {
            "status": "FAILED",
            "details": "Error while executing lambda function.",
            "error": str(e)
        }


