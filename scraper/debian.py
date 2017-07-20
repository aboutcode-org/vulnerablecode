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
import re
from urllib.request import urlopen

import bs4


DEBIAN_ROOT_URL = 'https://security-tracker.debian.org'


def extract_tracker_paths(html):
    """
    Return a list of tracker URL paths extracted from the given `html` input.
    """
    soup = bs4.BeautifulSoup(html, 'lxml')
    tracker_links = soup.findAll('a', href=re.compile('^/track+.*'))
    return [link.get('href') for link in tracker_links]


def extract_cves_from_tracker(html):
    """
    Return all CVEs extracted from the given `html` input.
    """
    cve_id = []
    package_name = []
    vulnerability_status = []
    soup = bs4.BeautifulSoup(html, 'lxml')

    for tag in soup.find_all('a'):
        href = tag.get('href')

        if re.search('/tracker/CVE-(.+)', href):
            id = re.findall('(?<=/tracker/).*', href)
            cve_id.append(id[0])

        if re.search('^/tracker/TEMP-+.*', href):
            id = re.findall('(?<=/tracker/).*', href)
            cve_id.append(id[0])

        if re.search('/tracker/source-package/(.+)', href):
            pkg = re.findall('(?<=/tracker/source-package/).*', href)
            package_name.append(pkg[0])

        # if package name is empty, use the previous package name
        if href == '/tracker/source-package/':
            package_name.append(pkg)

    for tag in soup.find_all('td'):
        if 'medium' in tag or 'low' in tag or 'not yet assigned' in tag:
            vulnerability_status.append(tag.text)
        elif tag.find_all('span', {'class': 'red'}) and tag.text == 'high**' or tag.text == 'high':
            vulnerability_status.append(tag.text)

    return cve_id, package_name, vulnerability_status


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
