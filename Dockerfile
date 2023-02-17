FROM amazon/aws-lambda-python:3.9
COPY ./code/ /code/
COPY ./template.yaml /code/
WORKDIR /code

RUN pip install --upgrade awscli aws-sam-cli tox setuptools
RUN sam build -m requirements.txt -t template.yaml
# execute tests
RUN tox -v
# validate sam template file
RUN sam validate -t template.yaml --lint