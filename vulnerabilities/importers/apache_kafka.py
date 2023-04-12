#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import logging

import pytz
import requests
from bs4 import BeautifulSoup
from dateutil.parser import parse
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference

logger = logging.getLogger(__name__)

# The entries below with `"action": "omit"` have no useful/reportable fixed or affected version data.
# See https://kafka.apache.org/cve-list
affected_version_range_mapping = {
    "CVE-2022-34917": {
        "action": "include",
        "2.8.0 - 2.8.1, 3.0.0 - 3.0.1, 3.1.0 - 3.1.1, 3.2.0 - 3.2.1": "affected",
        "2.8.2, 3.0.2, 3.1.2, 3.2.3": "fixed",
        "affected_version_range": "vers:apache/>=2.8.0|<=2.8.1|!=2.8.2|>=3.0.0|<=3.0.1|!=3.0.2|>=3.1.0|<=3.1.1|!=3.1.2|>=3.2.0|<=3.2.1|!=3.2.3",
        "Issue announced": "19 Sep 2022",
    },
    "CVE-2022-23302": {
        "action": "omit",
    },
    "CVE-2022-23305": {
        "action": "omit",
    },
    "CVE-2022-23307": {
        "action": "omit",
    },
    "CVE-2021-45046": {
        "action": "omit",
    },
    "CVE-2021-44228": {
        "action": "omit",
    },
    "CVE-2021-4104": {
        "action": "omit",
    },
    "CVE-2021-38153": {
        "action": "include",
        "2.0.0, 2.0.1, 2.1.0, 2.1.1, 2.2.0, 2.2.1, 2.2.2, 2.3.0, 2.3.1, 2.4.0, 2.4.1, 2.5.0, 2.5.1, 2.6.0, 2.6.1, 2.6.2, 2.7.0, 2.7.1, 2.8.0.": "affected",
        "2.6.3, 2.7.2, 2.8.1, 3.0.0 and later": "fixed",
        "affected_version_range": "vers:apache/2.0.0|2.0.1|2.1.0|2.1.1|2.2.0|2.2.1|2.2.2|2.3.0|2.3.1|2.4.0|2.4.1|2.5.0|2.5.1|2.6.0|2.6.1|2.6.2|!=2.6.3|2.7.0|2.7.1|!=2.7.2|2.8.0.|!=2.8.1|<3.0.0",
        "Issue announced": "21 Sep 2021",
    },
    "CVE-2019-12399": {
        "action": "include",
        "2.0.0, 2.0.1, 2.1.0, 2.1.1, 2.2.0, 2.2.1, 2.3.0": "affected",
        "2.2.2, 2.3.1 and later": "fixed",
        "affected_version_range": "vers:apache/2.0.0|2.0.1|2.1.0|2.1.1|2.2.0|2.2.1|!=2.2.2|2.3.0|<2.3.1",
        "Issue announced": "13 Jan 2020",
    },
    "CVE-2018-17196": {
        "action": "include",
        "0.11.0.0 to 2.1.0": "affected",
        "2.1.1 and later": "fixed",
        "affected_version_range": "vers:apache/>=0.11.0.0|<2.1.1",
        "Issue announced": "10 July 2019",
    },
    "CVE-2018-1288": {
        "action": "include",
        "0.9.0.0 to 0.9.0.1, 0.10.0.0 to 0.10.2.1, 0.11.0.0 to 0.11.0.2, 1.0.0": "affected",
        "0.10.2.2, 0.11.0.3, 1.0.1, 1.1.0": "fixed",
        "affected_version_range": "vers:apache/>=0.9.0.0|<=0.9.0.1|>=0.10.0.0|<=0.10.2.1|!=0.10.2.2|>=0.11.0.0|<=0.11.0.2|!=0.11.0.3|1.0.0|!=1.0.1|!=1.1.0",
        "Issue announced": "26 July 2018",
    },
    "CVE-2017-12610": {
        "action": "include",
        "0.10.0.0 to 0.10.2.1, 0.11.0.0 to 0.11.0.1": "affected",
        "0.10.2.2, 0.11.0.2, 1.0.0": "fixed",
        "affected_version_range": "vers:apache/>=0.10.0.0|<=0.10.2.1|!=0.10.2.2|>=0.11.0.0|<=0.11.0.1|!=0.11.0.2|!=1.0.0",
        "Issue announced": "26 July 2018",
    },
}


class ApacheKafkaImporter(Importer):

    GH_PAGE_URL = "https://raw.githubusercontent.com/apache/kafka-site/asf-site/cve-list.html"
    ASF_PAGE_URL = "https://kafka.apache.org/cve-list"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://www.apache.org/licenses/"

    @staticmethod
    def fetch_advisory_page(self):
        page = requests.get(self.GH_PAGE_URL)
        return page.content

    def advisory_data(self):
        advisory_page = self.fetch_advisory_page(self)

        parsed_data = self.to_advisory(advisory_page)
        return parsed_data

    def to_advisory(self, advisory_page):
        advisories = []

        advisory_page = BeautifulSoup(advisory_page, features="lxml")
        cve_section_beginnings = advisory_page.find_all("h2")
        for cve_section_beginning in cve_section_beginnings:
            # This sometimes includes text that follows the CVE on the same line -- sometimes there is a carriage return, sometimes there is not
            # cve_id = cve_section_beginning.text.split("\n")[0]
            # This is superior, gets only the cve id and no following text.
            cve_id = cve_section_beginning.get("id")

            cve_description_paragraph = cve_section_beginning.find_next_sibling("p")

            description = str(cve_description_paragraph.get_text())
            description = " ".join(description.split())

            cve_data_table = cve_section_beginning.find_next_sibling("table")
            cve_data_table_rows = cve_data_table.find_all("tr")
            affected_versions_row = cve_data_table_rows[0]
            fixed_versions_row = cve_data_table_rows[1]

            # Remove leading white space after initial comma
            affected_versions = affected_versions_row.find_all("td")[1].text

            affected_versions_clean = [v.strip() for v in affected_versions.split(",")]
            affected_versions_clean = [v for v in affected_versions if v]

            fixed_versions = fixed_versions_row.find_all("td")[1].text

            fixed_versions_clean = [v.strip() for v in fixed_versions.split(",")]
            fixed_versions_clean = [v for v in fixed_versions if v]

            cve_version_mapping = affected_version_range_mapping.get(cve_id)
            if not cve_version_mapping:
                logger.error(f"Data for {cve_id} not found in mapping. Skipping.")
            if cve_version_mapping and cve_version_mapping.get("action") == "include":
                # These 2 variables (not used elsewhere) trigger the KeyError for changed/missing data.
                check_affected_versions_key = cve_version_mapping.get(affected_versions) or []
                check_fixed_versions_key = cve_version_mapping.get(fixed_versions) or []

                if not check_affected_versions_key:
                    logger.error(f"Affected versions for {cve_id} not found in mapping. Skipping.")
                if not check_fixed_versions_key:
                    logger.error(f"Fixed versions for {cve_id} not found in mapping. Skipping.")

                references = [
                    Reference(
                        url=self.ASF_PAGE_URL,
                        reference_id=cve_id,
                    ),
                    Reference(
                        url=f"{self.ASF_PAGE_URL}#{cve_id}",
                        reference_id=cve_id,
                    ),
                    Reference(
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        reference_id=cve_id,
                    ),
                ]

                affected_packages = []
                affected_version_range = cve_version_mapping.get("affected_version_range")
                if cve_version_mapping.get("affected_version_range"):
                    affected_package = AffectedPackage(
                        package=PackageURL(
                            name="kafka",
                            type="apache",
                        ),
                        affected_version_range=affected_version_range,
                    )
                    affected_packages.append(affected_package)

                date_published = None
                issue_announced = cve_version_mapping.get("Issue announced")

                if issue_announced:
                    date_published = parse(issue_announced).replace(tzinfo=pytz.UTC)

                advisories.append(
                    AdvisoryData(
                        aliases=[cve_id],
                        summary=description,
                        affected_packages=affected_packages,
                        references=references,
                        date_published=date_published,
                    )
                )

        return advisories
