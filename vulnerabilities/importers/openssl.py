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
from bs4 import BeautifulSoup
from packageurl import PackageURL
from vulnerabilities.utils import get_item
from vulnerabilities.utils import fetch_response
from datetime import timezone
from dateutil import parser as dateparser

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from univers.version_range import OpensslVersionRange

logger = logging.getLogger(__name__)

class OpensslImporter(Importer):
    
    root_url = 'https://openssl-library.org/news/vulnerabilities/index.html'
    license_url = 'https://spdx.org/licenses/OpenSSL-standalone.html'
    spdx_license_expression = 'OpenSSL-standalone'

    def advisory_data(self):
        output_data = get_adv_data(self.root_url)
        for data in output_data:
            yield self.to_advisory(data)

    def to_advisory(self,data):
        #alias
        alias = get_item(data,"CVE")

        #published data
        date_published = get_item(data,'date_published')
        parsed_date_published = dateparser.parse(date_published, yearfirst=True).replace(
            tzinfo=timezone.utc
        )

        #affected packages
        affected_packages = []
        affected_package_out = get_item(data,'affected_packages')
        for affected in affected_package_out:
            if 'fips' in affected:
                break
            versions = re.findall(r"(?<=from\s)([^\s]+)|(?<=before\s)([^\s]+)", affected)
            versions = [v for group in versions for v in group if v] # Output: ['1.0.1', '1.0.1j']
            affected_version = OpensslVersionRange.from_versions(versions)
            affected_packages.append(AffectedPackage(
                package=PackageURL(
                    type="openssl",
                    name="openssl"
                ),
                affected_version_range=affected_version
            ))
        
        #Severity
        severity = VulnerabilitySeverity(
            system=SCORING_SYSTEMS["generic_textual"], value=get_item(data,"severity")
        )

        #Reference
        references = []
        for reference in get_item(data,"references"):
            references.append(Reference(
                severities=[severity],
                reference_id=alias,
                url=reference
            ))

        #summary
        summary = get_item(data,"summary")

        return AdvisoryData(
            aliases=alias,
            summary=summary,
            affected_packages=affected_packages,
            references=references,
            date_published=parsed_date_published,
            url=self.root_url+'#'+alias
        )

'''
The structure is like:
<h3> CVE
<dl>
    <dt>
    <dd>
in <dd> affected packages as <li>
in <dd> references as <li> <a>
'''
def get_adv_data(url):
    try:
        response = fetch_response(url).content
        soup = BeautifulSoup(response,'html.parser')
    except:
        logger.error(f"Failed to fetch URL {url}")

    advisories =[]

    #all the CVEs are h3 with id="CVE-.."
    for cve_section in soup.find_all("h3"):
        data_output = {
            "date_published" : '',
            "CVE" : '',
            "affected_packages" :[],
            "references" : [],
            "summary" : '',
            "severity" : ''
        }

        #CVE is in a link
        data_output["CVE"] = cve_section.find("a").text

        #the <dl> tag in this section
        dl = cve_section.find_next_sibling("dl")
        for dt,dd in zip(dl.find_all('dt'),dl.find_all('dd')): #combines both the lists,for better iteration 
            key = dt.text
            value = dd.text

            #Severity
            if key == "Severity":
                data_output["severity"] =value
            #Published Date
            elif key == "Published at":
                data_output['date_published'] = value
            #Affected Packages
            elif key == "Affected":
                affected_list = [li.text.strip() for li in dd.find_all("li")]
                data_output["affected_packages"] = affected_list
            #references
            elif key == "References":
                references = [a["href"] for a in dd.find_all("a")]
                data_output["references"] = references

        #for summary
        for sibling in dl.find_next_siblings():
            if sibling.name == "h2" or sibling.name == "h3":
                break
            if sibling.name == "p":
                if 'Issue summary:' in sibling.text:
                    data_output["summary"] = sibling.text.strip("Issue summary:")

    
        #append all the output  data to the list
        advisories.append(data_output)
    
    #return the list with all the advisory data
    return advisories

