#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import re
from typing import Dict
from typing import Iterable
from typing import List

import requests
from packageurl import PackageURL
from univers.version_range import RpmVersionRange

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.models import vulnerability
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.rpm_utils import rpm_to_purl
from vulnerabilities.utils import get_cwe_id
from vulnerabilities.utils import get_item
from vulnerabilities.utils import requests_with_5xx_retry

logger = logging.getLogger(__name__)

import requests
from bs4 import BeautifulSoup



class LifeRayImporter(Importer):
    spdx_license_expression = "CC-BY-4.0"
    
    importer_name = "Liferay Importer"
    url = "https://liferay.dev/portal/security/known-vulnerabilities"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        response = requests.get(self.url)
        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find_all(class_='h4 list-group-title text-truncate')
        for i in table:
            page = i.find('a')
            # print(page.text,end=" ")
            # print(page['href'])
            # soup2 = BeautifulSoup(requests.get(page['href']),'html.parser')
            """ This can not be automated as the html contains natural language and we need to build something to process unstructured data 
                So till now I am saving only the vulnerability id and url
            """
            id = page.text.split()
            Vulnerability.objects.create(vulnerability_id = id,summary = page.text.split()[1],affected_packages=[],url=page['href'],fixed_packages=[],reference=[],weakness=[],resource_url=self.url)
        # return AdvisoryData(
        #     aliases=aliases,
        #     summary=advisory_data.get("bugzilla_description") or "",
        #     affected_packages=affected_packages,
        #     references=references,
        #     weaknesses=cwe_list,
        #     url=resource_url
        #     if resource_url
        #     else "https://access.redhat.com/hydra/rest/securitydata/cve.json",
        # )
        return []

# def main():
#     importer = LifeRayImporter()
#     print(importer.advisory_data())
#     # for advisory_data in importer.advisory_data():
#     #     print(advisory_data)  # Or do something else with the data
# main()