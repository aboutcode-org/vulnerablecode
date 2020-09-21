FROM python:3.8

# PYTHONUNBUFFERED=1 ensures that the python output is set straight
# to the terminal without buffering it first
ENV PYTHONUNBUFFERED 1
RUN mkdir /vulnerablecode
WORKDIR /vulnerablecode
ADD . /vulnerablecode/
RUN pip install -r requirements.txt