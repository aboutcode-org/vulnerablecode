#!/usr/bin/env python
#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
# VulnerableCode is a trademark of nexB Inc.
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
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import json
from urllib.request import urlopen

ids = []
cvss = []
summary = []

def output_cve_id(type=None, name=None, version=None):
    """
    Outputs cve-ids, if any, related to a package.
    Take as input, a package name, type, package version and
    query cve-search' dataset for any reported vulnerabilities
    """
    if not name:
        return

    if version:
        url = f'https://cve.circl.lu/api/search/{name}/{version}'
    else:
        url = f'https://cve.circl.lu/api/search/{name}'

    raw_data = urlopen(url).read()
    data = json.loads(raw_data)

    """
    Extract CVE-IDs & CVSS scores associated with
    a package.
    """
    if data and name and not version:
        for item in data['data']:
            try:
                ids.append(item['id'])
                cvss.append(item['cvss'])
                summary.append(item['summary'])
            except TypeError:
                cvss.append(None)

        return ids, cvss, summary

    if data and version:
        for item in data:
            try:
                ids.append(item['id'])
                cvss.append(item['cvss'])
                summary.append(item['summary'])
            except TypeError:
                cvss.append(None)

        return ids, cvss, summary
