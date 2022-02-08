FROM python:3.8

# Force unbuffered stdout and stderr (i.e. they are flushed to terminal immediately)
ENV PYTHONUNBUFFERED 1

RUN mkdir /opt/vulnerablecode && \
    mkdir -p /var/vulnerablecode/static/
WORKDIR /opt/vulnerablecode
COPY . .
RUN python -m pip install --upgrade pip && \
    pip install -r requirements.txt
