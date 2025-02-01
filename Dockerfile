# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects

FROM python:3.9

WORKDIR /app

# Labels 
LABEL org.opencontainers.image.source="https://github.com/aboutcode-org/vulnerablecode"
LABEL org.opencontainers.image.title="VulnerableCode"
LABEL org.opencontainers.image.documentation="https://vulnerablecode.readthedocs.io/en/latest/introduction.html"
LABEL org.opencontainers.image.version="v35.1.0"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Python settings: Force unbuffered stdout and stderr (i.e. they are flushed to terminal immediately)
ENV PYTHONUNBUFFERED 1
# Python settings: do not write pyc files
ENV PYTHONDONTWRITEBYTECODE 1

RUN mkdir -p /var/vulnerablecode/static

# Keep the dependencies installation before the COPY of the app/ for proper caching
COPY setup.cfg setup.py requirements.txt pyproject.toml /app/
RUN pip install . -c requirements.txt

COPY . /app
