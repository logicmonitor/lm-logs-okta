FROM python:3.9
COPY ./code/ /code/
COPY ./template.yaml /code/
WORKDIR /code
RUN pip install --upgrade pip && pip install --upgrade awscli aws-sam-cli tox setuptools
# execute unit tests
RUN tox -v
# # validate sam template file
RUN sam validate -t template.yaml --lint
# create lambda zip artifact
RUN apt update && apt install zip -y
RUN mkdir -p lambda-pkg/oktalogcollector
RUN pip install -r requirements.txt --target lambda-pkg
RUN cp src/oktalogcollector/*.py lambda-pkg/oktalogcollector/
RUN zip -r lambda.zip lambda-pkg
