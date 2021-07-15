FROM python:3.9.6

# Force unbuffered stdout and stderr (i.e. they are flushed to terminal immediately)
ENV PYTHONUNBUFFERED 1

RUN mkdir /vulnerablecode
WORKDIR /vulnerablecode
COPY . /vulnerablecode/
RUN python -m pip install --upgrade pip && \
		pip install -r requirements.txt
