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

import logging
from urllib.request import urlopen
import json

import bs4

DEBIAN_ROOT_URL = "https://security-tracker.debian.org/tracker/data/json"


def debian_extract_data():
    """
    Return all CVEs extracted from the given `html` input.
    """
    test_input = urlopen("https://security-tracker.debian.org/tracker/data/json").read()

    fields_names = ['status', 'urgency', 'fixed_version']

    return [{name: version_detail.get(name) for name in fields_names}
            for package_name, vulnerabilities in data.items()
            for vulnerability, details in vulnerabilities.items()
            for distro, version_detail in details.get('releases', {'jessie'}).items()]


def scrape_cves():
    """
    Runs the full scraping process of Debian CVEs.
    """
    tracker_root_html = urlopen(f'{DEBIAN_ROOT_URL}/tracker/').read()
    tracker_paths = extract_tracker_paths(tracker_root_html)

    cves = []
    for tracker_path in tracker_paths:
        tracker_url = f'{DEBIAN_ROOT_URL}{tracker_path}/'
        logging.info(f'Visiting: {tracker_url}')
        html = urlopen(tracker_url).read()
        cves.append(extract_cves_from_tracker(html))

    return cves
