FROM amazon/aws-lambda-python:3.9
COPY ./code/ /code/
COPY ./template.yaml /code/
WORKDIR /code

RUN pip install --upgrade awscli aws-sam-cli tox setuptools
RUN sam build -m requirements.txt -b package
# execute tests
RUN tox -v
# validate sam template file
RUN sam validate -t template.yaml --lint

# create lambda zip artifact
RUN yum install zip -y
RUN mkdir -p lambda-pkg
WORKDIR /code/.aws-sam/build/oktaLogCollector
RUN zip -r9 /code/lambda-pkg/lambda.zip .
# RUN ls package -la
# RUN ls .aws-sam/build/oktaLogCollector -la
VOLUME /code/lambda-pkg