FROM python:3.9 as base
COPY ./code/ /code/
COPY ./template.yaml /code/
WORKDIR /code
RUN pip install --upgrade pip && pip install --upgrade awscli aws-sam-cli tox setuptools

FROM base as buildAndTest
# execute unit tests
RUN tox -rv
# # validate sam template file
RUN sam validate -t template.yaml --lint
# create lambda zip artifact
RUN apt update && apt install zip -y
RUN mkdir -p lambda-pkg/oktalogcollector
RUN pip install -r requirements.txt --target lambda-pkg
RUN cp src/oktalogcollector/*.py lambda-pkg/oktalogcollector/
WORKDIR /code/lambda-pkg
RUN zip -r lambda.zip .

FROM debian as release 
WORKDIR /code
COPY --from=buildAndTest /code/lambda-pkg/lambda.zip /code/lambda-pkg/
VOLUME /code