FROM python@sha256:e9b7e3b4e9569808066c5901b8a9ad315a9f14ae8d3949ece22ae339fff2cad0

# PYTHONUNBUFFERED=1 ensures that the python output is set straight
# to the terminal without buffering it first
ENV PYTHONUNBUFFERED 1
RUN mkdir /vulnerablecode
WORKDIR /vulnerablecode
ADD . /vulnerablecode/
RUN pip install -r requirements.txt

LABEL "base_image": "pkg:docker/python@sha256%3Ae9b7e3b4e9569808066c5901b8a9ad315a9f14ae8d3949ece22ae339fff2cad0"
LABEL "dockerfile_url":  "https://github.com/nexB/vulnerablecode/blob/develop/Dockerfile"
LABEL "homepage_url":  "https://github.com/nexB/vulnerablecode"
LABEL "license": "Apache-2.0"