#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import json
import logging
import re
from datetime import timezone
from typing import Iterable
import gzip
import io
from xml.etree import ElementTree as ET

import requests
from bs4 import BeautifulSoup
from dateutil import parser as dateparser
from packageurl import PackageURL
from univers.version_range import GenericVersionRange
from univers.version_range import VersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline
from vulnerabilities.severity_systems import GENERIC
from vulnerabilities.severity_systems import CVSSV31
from vulnerabilities.utils import fetch_response
from vulnerabilities.utils import get_item

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BottleRocketImporterPipeline(VulnerableCodeBaseImporterPipeline):
    """Collect Advisories from BottleRocket"""

    pipeline_id = "bottlerocket_importer"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/bottlerocket-os/bottlerocket/blob/develop/LICENSE-APACHE"
    root_url = "https://advisories.bottlerocket.aws/updateinfo.xml.gz"
    importer_name = "Bottle Rocket Importer"

    def __init__(self):
        super().__init__()

    @classmethod
    def steps(cls):
        return (
            cls.collect_and_store_advisories,
            cls.import_new_advisories,
        )

    # num of advisories
    def advisories_count(self) -> int:
        return len(fetch_advisory_data(self.root_url))

    # parse the response data
    def collect_advisories(self) -> Iterable[AdvisoryData]:
        advisory_data = fetch_advisory_data(self.root_url) #list

        for data in advisory_data:
            yield to_advisory_data(data)



def fetch_advisory_data(url):
    """Fetches advisory data from the gzipped xml file,returns a list"""
    response = requests.get(url, stream=True)

    if response.status_code == 200:
        with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as gz:
            xml_content = gz.read()
        
        #parsing the xml content
        root = ET.fromstring(xml_content)

        #extract and filter updates
        filtered_updates = [] #list containing dicts
        """each element looks like this
        {
            'issued_date': '2025-03-07T01:00:15Z', 
            'severity': 'important', 
            'description': 'In the Linux kernel, the following vulnerability has been resolved: ext4: fix timer use-after-free on failed mount', 
            'references': [
                {
                    'href': 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49960', 
                    'id': 'CVE-2024-49960', 
                    'type': 'cve'
                }, 
                {
                    'href': 'https://github.com/bottlerocket-os/bottlerocket-kernel-kit/blob/develop/advisories/1.2.1/BRSA-th6e2wrokkoq.toml', 
                    'id': 'BRSA-th6e2wrokkoq', 
                    'type': 'brsa'
                }
            ], 
            'packages': [
                {
                    'arch': 'x86_64', 
                    'name': 'kernel-5.10', 
                    'version': '5.10.234', 
                    'release': '1.1741301886.9165eb8.br1', 
                    'epoch': '0'
                }
            ]
        }
        """
        for update in root.findall('update'):
            filtered_packages = [] #filtered packages with arch='x86_64' : [{'arch': 'x86_64', 'name': 'kernel-5.15', 'version': '5.15.178', 'release': '1.1740527062.132b0a1.br1', 'epoch': '0'}, {'arch': 'x86_64', 'name': 'bottlerocket-kernel-5.15', 'version': '5.15.178', 'release': '1.1740527062.132b0a1.br1', 'epoch': '0'}]
            for pkg in update.find('pkglist').find('collection').findall('package'):
                if pkg.attrib['arch'] == 'x86_64': 
                    filtered_packages.append(pkg.attrib)  

            filtered_update = {
                'issued_date': update.find('issued').attrib['date'],
                'severity': update.find('severity').text,
                'description': update.find('description').text,
                'references': [ref.attrib for ref in update.find('references').findall('reference')], #contains the cve id
                'packages': filtered_packages
            }
            filtered_updates.append(filtered_update)

        return filtered_updates       
    else:
        print(f"failed to fetch the file.Code:{response.status_code}")



def to_advisory_data(raw_data) -> AdvisoryData:
    """Parses extracted data to Advisory Data"""

    #aliases
    aliases = []

    # severity
    severity = VulnerabilitySeverity(
        system=GENERIC,
        value=get_item(raw_data,"severity")
    )

    #references
    filtered_references = []
    references = get_item(raw_data,"references") # a list
    for reference in references:
        url = get_item(reference,"href")
        id = get_item(reference,"id")
        filtered_references.append(
            Reference(
                severities=[severity],
                reference_id=id,
                url=url
            )
        )
        aliases.append(id)


    # affected packages
    filtered_affected_packages = []
    affected_packages = get_item(raw_data, "packages")  # list of dicts
    for package in affected_packages:
        package_name = get_item(package,"name")
        fix_version = get_item(package,"version")
        filtered_affected_packages.append(
            AffectedPackage(
                package=PackageURL(type="bottle-rocket", name=package_name),
                affected_version_range=VersionRange.from_native(f"<{fix_version}"),
                fixed_version=SemverVersion(fix_version)
            )
        )

    # description
    description = get_item(raw_data, "description")

    # date published
    date_published = get_item(raw_data, "issued_date")
    date_published = dateparser.parse(date_published, yearfirst=True).replace(tzinfo=timezone.utc)

    return AdvisoryData(
        aliases=aliases,
        summary=description,
        affected_packages=filtered_affected_packages,
        references=filtered_references,
        date_published=date_published,
    )