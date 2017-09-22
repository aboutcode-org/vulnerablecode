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

from urllib.request import urlopen

import bs4


UBUNTU_ROOT_URL = 'https://people.canonical.com/~ubuntu-security/cve/main.html'


def extract_cves(html):
    soup = bs4.BeautifulSoup(html, 'lxml')

    # Exclude the header row which has no class attribute
    rows = soup.find_all('tr', attrs={'class': True})

    cves = []
    for row in rows:
        columns = row.text.split()
        cves.append({
            'cve_id': columns[0],
            'package_name': columns[1],
            'vulnerability_status': row.get('class')[0],
        })

    return cves


def scrape_cves():
    """
    Runs the full scraping process of Ubuntu CVEs.
    """
    html = urlopen(UBUNTU_ROOT_URL).read()
    cves = extract_cves(html)
    return cves
