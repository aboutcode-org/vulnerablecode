#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import re
from datetime import datetime
from datetime import timezone

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from vulnerabilities.utils import get_item
from vulnerabilities.utils import fetch_response
from urllib.parse import urljoin

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from univers.versions import SemverVersion
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import SCORING_SYSTEMS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__) 

class YubicoImporter(Importer):

    root_url = "https://www.yubico.com/support/security-advisories/"
    spdx_license_expression = "NOASSERTION"
    importer_name = "Yubico Security Bulletin Importer"

    def advisory_data(self):
        urls = fetch_links(self.root_url)
        for url in urls:
            yield self.to_advisory(url)

    def to_advisory(self,url):
        output_generated = get_adv_data(url)

        severity = VulnerabilitySeverity(
            system=SCORING_SYSTEMS["cvssv3.1"],
            value=get_item(output_generated,"score")
        )

        reference = Reference(
            reference_id=get_item(output_generated,"cve"),
            severities=severity,
            url=url
        )

        affected_packages = []
        try:
            for affected_package in get_item(output_generated,"affected_packages"):
                print(affected_package)
                fixed_version = SemverVersion(get_item(affected_package,"version"))
                affected_packages.append(AffectedPackage(
                    package=PackageURL(
                        type="generic",
                        name=get_item(affected_package,"package")
                    ),
                    fixed_version=fixed_version
                ))
        except:
            pass

        try:
            date_published = datetime.strptime(
                get_item(output_generated,"published_date") or "", "%Y-%m-%d"
            ).replace(tzinfo=timezone.utc)
        except:
            date_published =''

        return AdvisoryData(
            aliases=get_item(output_generated,'cve'),
            summary=get_item(output_generated,'summary'),
            affected_packages=affected_packages,
            references=reference,
            date_published=date_published,
            url=url
        )



#to fetch all the links in advisory page 
'''
link structure : https://www.yubico.com/support/security-advisories/ysa-2024-03/
href : /support/issue-rating-system/security-advisories/ysa-2017-01/
       https://www.yubico.com/support/security-advisories/ysa-2025-01/
'''
root_url = "https://www.yubico.com/support/security-advisories/"
def fetch_links(url):
    links = []
    try:
        data = fetch_response(url).content
        soup = BeautifulSoup(data,features="lxml")
        for a_tag in soup.find_all('a'):
            link = a_tag.get("href")
            if '/security-advisories/ysa-' in link:
                #links to all the advisories
                links.append(urljoin(url, link)) 
    except:
        logger.error(f"Failed to fetch URL {url}")
    
    return links

#get advisory data from each link
''' data available
Published Date: 2025-01-14
Tracking IDs: YSA-2025-01
CVE: <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43399">CVE-2021-43399</a>
CVSS Severity: <a href="https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N&amp;version=3.1" target="_blank" rel="noreferrer noopener">4.4</a>
Summary : h2 id="h-security-advisory.." <strong>
references
affected software: <h3 class="wp-block-heading" id="h-affected...">Affected products</h3> the next <p> contains softwares till the next <h3>
timeline: <h3 id="h-timeline">Timeline</h3> then <table>
'''
#adv_link = 'https://www.yubico.com/support/security-advisories/ysa-2020-04/'
def get_adv_data(url):
    data = fetch_response(url).content
    soup = BeautifulSoup(data,'html.parser')
    output ={
        'published_date':'',
        'summary':'',
        'cve':'',
        'score':'',
        'affected_packages':[],
        'timeline_dates':[],
        'timeline_summaries':[]
    }

    #for affected software
    pattern = re.compile(
        r"(?P<package>[A-Za-z0-9\s\-_]+?)\s(?:with a version|versions?|prior to|Release version)\s*(?P<version>\d{4}\.\d{2}|\d+\.\d+\.\d+|\d+\.\d+)"
    )
    try:
        affected_soft_html = soup.select("[id^=h-affected]")[0]
        for sibling in affected_soft_html.find_next_siblings():#to get the next html elements
            if sibling.name == 'h3':  # Stop when another <h3> is found
                break
            if sibling.name == 'p':   # Collect <p> tags
                #sibling.text
                matches = pattern.findall(sibling.text)
                affected_packages = [{"package": match[0].strip(), "version": match[1]} for match in matches]
                for item in affected_packages:
                    output['affected_packages'].append(item)
                #output['affected_software'].append(sibling.text.strip())
    except:
        pass


    #for timeline
    timeline_td = soup.find_all('td')
    for i in range(len(timeline_td)):
        #odd for date,even for summary
        if i%2==0:
            output["timeline_dates"].append(timeline_td[i].text)
        else:
            output["timeline_summaries"].append(timeline_td[i].text)

    #for summary
    summary_html = soup.select("[id^=h-security-advisory]")[1]
    summary_pattern = r"Security Advisory(?:\sYSA-\d{4}-\d{2})?\s*[-–]?\s*" 
    cleaned_summary = re.sub(summary_pattern, "", summary_html.text).strip()
    output['summary'] = cleaned_summary

    #for published date
    all_paras = soup.find_all('p')
    try:
        for para in all_paras:
            if 'Published' in para.text:
                date_match = re.search(r'Published Date:\s*(\d{4}-\d{2}-\d{2})', para.text)
                published_date = date_match.group(1)
                output['published_date'] = published_date
    except:
        pass

    #for links cve and score
    for a_tag in soup.find_all('a'):
        link = a_tag.get("href")
        if 'cve' in link:
            #print(link)
            output["cve"] = a_tag.text
        if 'cvss' in link:
            #print(link)
            output["score"]=a_tag.text
    return output

