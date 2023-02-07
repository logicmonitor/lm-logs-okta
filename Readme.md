# OKTA Log Collector for LM-Logs


## Deploy as CloudFormation stack
[![Launch Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home#/stacks/create/review?stackName=lm-okta-log-collector&templateURL=https://okta-log-collector-src.s3.amazonaws.com/template-0.0.1.yaml)


### Requirements

* AWS CLI 
* [SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html) >=0.7 installed
* [Python 3 installed](https://www.python.org/downloads/)
* [Docker installed](https://www.docker.com/community-edition) only for local development
* [Virtualenvwrapper](https://virtualenvwrapper.readthedocs.io/en/latest/) or roll your own with [Python Virtual Environment](http://docs.python-guide.org/en/latest/dev/virtualenvs/)

### Python 3.9

## Deploying as AWS lambda function

Build SAM locally
```bash
> sam build -m requirements.txt
```

Deploy SAM
```bash
> sam deploy --guided
```

## Parameters
| Parameter                  | Description                                                                                                                                                                                                                                 | Default                                                                                                            |
|----------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| FunctionName               | The name for lambda function.                                                                                                                                                                                                               | LM-Okta-Log-Collector                                                                                              |
| LMCompanyName              | The LogicMonitor account name.                                                                                                                                                                                                              | -                                                                                                                  |
| LMAccessId                 | The LM API tokens access ID                                                                                                                                                                                                                 | -                                                                                                                  |
| LMAccessKey                | The LM API tokens access key                                                                                                                                                                                                                | -                                                                                                                  |
| OktaDomain                 | Okta domain eg "company.okta.com".                                                                                                                                                                                                          | -                                                                                                                  |
| OktaAPIKey                 | Okta API key to fetch logs from okta.                                                                                                                                                                                                       | -                                                                                                                  |
| LMLogsServiceName          | This will be used for anomaly detection.                                                                                                                                                                                                    | okta-system-logs                                                                                                   |
| LMResourceId               | Ignored when LMLogsServiceName is specified. Is a json for resource mapping. if specified as {\"system.hostname\" : \"prod-node-us-west-1\"} all logs will be mapped against the device with property system.hostname = prod-node-us-west-1 | -                                                                                                                  |
| IncludeMetadataKeys        | comma separated keys to add as event metadata in a lm-log event. for nested json specify '.' eg - actor.displayname,actor.type                                                                                                              | 'severity,actor.displayname,actor.type,actor.alternateId,client.geographicalContext.city,displayMessage,eventType' |
| ScheduleExpression         | Cron expression for this lambda function. "rate(2 minutes)" means, function will be triggered every 2 minutes. see https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html for more details.                        | "rate(2 minutes)"                                                                                                  |
| FunctionMemorySize         | The memory size for the OKTA Log Collector lambda function in MBs                                                                                                                                                                           | 2048                                                                                                                |
| FunctionTimeoutInSeconds   | The timeout for the OKTA Log Collector lambda function in Seconds                                                                                                                                                                           | 110                                                                                                                |

