#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
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
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import json
from urllib.request import urlopen

DEBIAN_TRACKER_URL = 'https://security-tracker.debian.org/tracker/data/json'


def extract_vulnerabilities(debian_data, base_release='jessie'):
    """
    Return a sequence of mappings for each existing combination of
    package and vulnerability from a mapping of Debian vulnerabilities
    data.
    """
    package_vulnerabilities = []

    for package_name, vulnerabilities in debian_data.items():
        if not vulnerabilities or not package_name:
            continue

        for vulnerability, details in vulnerabilities.items():
            releases = details.get('releases')
            if not releases:
                continue

            release = releases.get(base_release)
            if not release:
                continue

            # the latest version of this package in base_release
            version = release.get('repositories', {}).get(base_release, '')

            package_vulnerabilities.append({
                'package_name': package_name,
                'vulnerability_id': vulnerability,
                'description': details.get('description', ''),
                'status': release.get('status', ''),
                'urgency': release.get('urgency', ''),
                'version': version,
                'fixed_version': release.get('fixed_version', '')
            })

    return package_vulnerabilities


def scrape_vulnerabilities():
    """
    Scrape debian' security tracker.
    """
    json_content = urlopen(DEBIAN_TRACKER_URL).read()
    return extract_vulnerabilities(json.loads(json_content))
