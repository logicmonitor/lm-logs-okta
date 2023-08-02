# OKTA Log Collector for LM-Logs

This integration provides an AWS cloudformation stack which includes a lambda function periodically collecting Okta system logs and forwarding it to Logicmonitor LM Logs.

## Deploy as CloudFormation stack
[![Launch Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home#/stacks/create/review?stackName=lm-okta-log-collector&templateURL=https://lm-logs-okta-collector.s3.amazonaws.com/stable/latest.yaml)



## Parameters
| Parameter                  | Description                                                                                                                                                                                                                                 | Default                                                                                                            |
|----------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| FunctionName               | The name for lambda function.                                                                                                                                                                                                               | LM-Okta-Log-Collector                                                                                              |
| LMCompanyName              | The LogicMonitor account name.                                                                                                                                                                                                              | -                                                                                                                  |
| LMAccessId                 | The LM API tokens access ID                                                                                                                                                                                                                 | -                                                                                                                  |
| LMAccessKey                | The LM API tokens access key                                                                                                                                                                                                                | -                                                                                                                  |
| LMBearerToken                | The LM API Bearer token. (You must specify LMBearerToken if not providing LMAccessId, LMAccessKey. In case you provide all, LMAccessId and LMAccessKey will be used to authenticate with Logicmonitor.  ) key                                                                                                                                                                                                                | -                                                                                                                  |
| OktaDomain                 | Okta domain eg "company.okta.com".                                                                                                                                                                                                          | -                                                                                                                  |
| OktaAPIKey                 | Okta API key to fetch logs from okta.                                                                                                                                                                                                       | -                                                                                                                  |
| LMLogsServiceName          | This will be used for anomaly detection.                                                                                                                                                                                                    | okta-system-logs                                                                                                   |
| LMResourceId               | Ignored when LMLogsServiceName is specified. Is a json for resource mapping. if specified as {\"system.hostname\" : \"prod-node-us-west-1\"} all logs will be mapped against the device with property system.hostname = prod-node-us-west-1 | -                                                                                                                  |
| IncludeMetadataKeys        | comma separated keys to add as event metadata in a lm-log event. for nested json specify '.' eg - actor.displayname,actor.type                                                                                                              | 'severity,actor.displayname,actor.type,actor.alternateId,client.geographicalContext.city,displayMessage,eventType' |
| ScheduleExpression         | Cron expression for this lambda function. "rate(2 minutes)" means, function will be triggered every 2 minutes. see https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html for more details.                        | "rate(2 minutes)"                                                                                                  |
| FunctionMemorySize         | The memory size for the OKTA Log Collector lambda function in MBs                                                                                                                                                                           | 2048                                                                                                                |
| FunctionTimeoutInSeconds   | The timeout for the OKTA Log Collector lambda function in Seconds                                                                                                                                                                           | 110                                                                                                                |
