# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import json
import re

import requests
import toml
import yaml


def load_yaml(path):
    with open(path) as f:
        return yaml.safe_load(f)


def load_json(path):
    with open(path) as f:
        return json.load(f)


def load_toml(path):
    with open(path) as f:
        return toml.load(f)


# FIXME: this is NOT how etags work .
# We should instead send the proper HTTP header
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-None-Match
# and integrate this finely in the processing as this typically needs to use
# streaming=True requests, and proper handling of the HTTP return code
# In all cases this ends up being a single request, not a HEADD followed
# by another real request
def create_etag(data_src, url, etag_key):
    """
    Etags are like hashes of web responses. For a data source `data_src`,
    we maintain (url, etag) mappings in the DB.  `create_etag`  creates
    (`url`, etag) pair. If a (`url`, etag) already exists then the code
    skips processing the response further to avoid duplicate work.

    `etag_key` is the name of header which contains the etag for the url.
    """
    etag = requests.head(url).headers.get(etag_key)
    if not etag:
        return True

    elif url in data_src.config.etags:
        if data_src.config.etags[url] == etag:
            return False

    data_src.config.etags[url] = etag
    return True


is_cve = re.compile(r"CVE-\d+-\d+", re.IGNORECASE).match
