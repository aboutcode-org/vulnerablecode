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

import bs4 as bs
import re
from urllib.request import urlopen


def debian_data():
    cve_id = []
    package_name = []
    vulnerability_status = []
    links = []

    parent_url = urlopen("https://security-tracker.debian.org/tracker/")
    data = bs.BeautifulSoup(parent_url, "lxml")

    return data


def extracted_data_debian(data):
    # Extract links of child datasets
    for tag in soup.find_all('a'):
        href = tag.get('href')

        if re.findall('^/track+.*', href):
            links.append(href)

    for child_links in range(6):
        # Extract package info from all the child datasets
        child_url = urlopen("https://security-tracker.debian.org"
                            + links[child_links + 2])
        soup = bs.BeautifulSoup(child_url, "lxml")

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
            if href == "/tracker/source-package/":
                package_name.append(pkg)

        for tag in soup.find_all('td'):

            if "medium**" in tag or "medium" in tag or "low" in tag or "low**" in tag or "not yet assigned" in tag:
                vulnerability_status.append(tag.text)
            elif tag.find_all("span", {"class": "red"}) and tag.text == "high**" or tag.text == "high":
                vulnerability_status.append(tag.text)

    return cve_id, package_name, vulnerability_status
