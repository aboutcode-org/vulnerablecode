FROM python:3.8
ENV PYTHONUNBUFFERED 1
RUN mkdir /vulnerablecode
WORKDIR /vulnerablecode
ADD . /vulnerablecode/
RUN pip install -r requirements.txt