# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects

FROM python:3.9

WORKDIR /app

# Python settings: Force unbuffered stdout and stderr (i.e. they are flushed to terminal immediately)
ENV PYTHONUNBUFFERED 1
# Python settings: do not write pyc files
ENV PYTHONDONTWRITEBYTECODE 1

RUN mkdir -p /var/vulnerablecode/static

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
       wait-for-it \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Keep the dependencies installation before the COPY of the app/ for proper caching
COPY setup.cfg setup.py requirements.txt pyproject.toml /app/
RUN pip install . -c requirements.txt

COPY . /app

# Store commit hash for docker deployment from local checkout.
RUN if [ -d ".git" ]; then \
  GIT_COMMIT=$(git rev-parse --short HEAD) && \
  echo "VULNERABLECODE_GIT_COMMIT=\"$GIT_COMMIT\"" >> /app/vulnerablecode/settings.py; \
  rm -rf .git; \
fi
