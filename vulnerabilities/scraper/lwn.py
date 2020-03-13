# Author: Islam Hiko (@EslamHiko)
# Copyright (c) 2020 nexB Inc. and others. All rights reserved.
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

from bs4 import BeautifulSoup as bs
from urllib.request import urlopen
import re


base_url = "https://lwn.net/"


def extractPackageData(advisoryLink, dist, advisoryId):

    content = urlopen(advisoryLink).read()
    soup = bs(content, "html.parser")
    text = soup.find('div', {'class': 'ArticleText'}).get_text()
    phrases = text.split('\n')
    cves = []
    references = []
    summary = ""
    for i in range(len(phrases)):
        words = phrases[i].split()
        if phrases[i].startswith('Subject:'):
            summary = phrases[i + 1].strip()
        for word in words:
            if word.startswith('CVE-') and word != 'CVE-ID':
                cves.append(word)
            elif word.startswith('https://') or word.startswith('http://'):
                references.append(word)

    cves = list(set(cves))

    dist = re.sub(r'\W+', '', dist).replace('_', '').lower()

    return {
        'cve_ids': cves,
        'references': references,
        'summary': summary,
        'advisory_id': advisoryId,
        'distributor': dist,
        'advisory_link': advisoryLink}


def getDistributors():
    url = base_url + "Alerts/"
    content = urlopen(url).read()
    soup = bs(content, "html.parser")
    dists = []
    distsLinks = []
    tables = soup.find_all('table', {'cellspacing': "4", })

    for table in tables:
        distsLinks += table.find_all('a')

    for a in distsLinks:
        dists.append(a['href'])

    return dists


def scrape_vulnerabilities():
    dists = getDistributors()
    packagesVulns = {}
    for dist in dists:
        distUrl = base_url + "Alerts/" + dist + "?n=100"
        distContent = urlopen(distUrl).read()
        distSoup = bs(distContent, "html.parser")
        articleSoup = distSoup.find('div', {'class': 'ArticleText'})
        text = articleSoup.get_text()
        total = int(text[text.find("(") + 1:text.find(")")].split()[0])
        for curr_offset in range(0, total, 100):

            table = articleSoup.find('table', {'cellpadding': 4})

            data = table.find_all('tr')
            data = data[1:]
            for row in data:
                rowElements = row.find_all('td')
                aTag = rowElements[0].find('a')
                advisoryLink = base_url[:-1] + aTag['href']
                advisoryId = aTag.get_text()
                package_names = rowElements[1].get_text().split(',')
                date = rowElements[2].get_text()
                for package_name in package_names:
                    extracted_data = extractPackageData(
                        advisoryLink, dist, advisoryId)
                    if packagesVulns.get(package_name):
                        packagesVulns[package_name].append(extracted_data)
                    else:
                        packagesVulns[package_name] = [extracted_data]

            distUrl = distUrl + "&offset=" + str(curr_offset)
            distSoup = bs(distContent, "html.parser")
            articleSoup = distSoup.find('div', {'class': 'ArticleText'})

    return packagesVulns
