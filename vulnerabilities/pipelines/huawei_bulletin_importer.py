#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import logging
from typing import Iterable, Tuple
from datetime import datetime
from datetime import timezone

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.version_range import VersionRange
from univers.versions import GenericVersion 

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline
from vulnerabilities.severity_systems import GENERIC

logger = logging.getLogger(__name__)


def extract_version(version_str: str) -> Tuple[str, str]:
    """
    Gets the version type and number from a messy Huawei version string.
    Returns tuple of (type, version) - returns empty type if cant parse
    """
    version_str = version_str.lower().strip()
    if version_str.startswith("harmonyos"):
        return "harmonyos", version_str.split("harmonyos")[-1].strip()
    elif version_str.startswith("emui"):
        return "emui", version_str.split("emui")[-1].strip()
    return "", version_str


class HuaweiBulletinImporterPipeline(VulnerableCodeBaseImporterPipeline):
    """
    Scrapes security bullitin data from Huawei's website:
    https://consumer.huawei.com/en/support/bulletin/
    """
    pipeline_id = "huawei_bulletin_importer"
    spdx_license_expression = "LicenseRef-Terms-Of-Use"  
    license_url = "https://consumer.huawei.com/en/legal/terms-of-use/"
    url = "https://consumer.huawei.com/en/support/bulletin/"
    importer_name = "Huawei Bulletin Importer"

    def __init__(self):
        super().__init__()
        self.raw_data = None 

    @classmethod
    def steps(cls):
        """The steps we need to run in order"""
        return (
            cls.fetch_bulletin,  
            cls.collect_and_store_advisories,  
            cls.import_new_advisories,  
        )

    def fetch_bulletin(self):
        """
        Gets the bullitin data from Huawei's site.
        Stores raw html for processing later.
        """
        self.log(f"Fetching {self.url}")
        try:
            response = requests.get(f"{self.url}2024/9/")
            response.raise_for_status()
            self.raw_data = BeautifulSoup(response.text, "html.parser")
        except Exception as e:
            self.log(f"Failed to fetch Huawei bulletin: {e}", logging.ERROR)
            raise

    def advisories_count(self) -> int:
        """
        Counts how many advisorys we found.
        Returns 0 if something went wrong.
        """
        if not self.raw_data:
            return 0

        tables = self.raw_data.find_all("table")
        if not tables: 
            return 0
        huawei_rows = len(tables[0].find_all("tr")[1:])  
        thirdparty_rows = len(tables[1].find_all("tr")[1:])  
        return huawei_rows + thirdparty_rows  

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        """
        Parse the bullitin and extract all the advisorys.
        Returns empty list if something goes wrong.
        """
        if not self.raw_data:
            return []

        tables = self.raw_data.find_all("table")
        if len(tables) < 2:  
            return []

        for row in tables[0].find_all("tr")[1:]: 
            cols = row.find_all("td")
            if len(cols) != 5: 
                continue
            advisory = {
                "cve_id": cols[0].text.strip(),
                "description": cols[1].text.strip(),
                "impact": cols[2].text.strip(),
                "severity": cols[3].text.strip(),
                "affected_versions": cols[4].text.strip(),
                "is_huawei": True
            }
            advisory_data = self.to_advisory_data(advisory)
            if advisory_data: 
                yield advisory_data
        for row in tables[1].find_all("tr")[1:]:  
            cols = row.find_all("td")
            if len(cols) != 3: 
                continue

            advisory = {
                "cve_id": cols[0].text.strip(),
                "severity": cols[1].text.strip(),
                "affected_versions": cols[2].text.strip(),
                "is_huawei": False
            }
            advisory_data = self.to_advisory_data(advisory)
            if advisory_data:
                yield advisory_data

    def to_advisory_data(self, data) -> AdvisoryData:
        """
        Takes raw data and makes it into propper advisory format.
        Returns None if theres any problems.
        """
        try:
            if not data.get("cve_id"):
                return None
            affected_packages = []
            versions = [v.strip() for v in data["affected_versions"].split(",") if v.strip()]
            
            for version in versions:
                system_type, version_number = extract_version(version)
                if not system_type: 
                    continue
                affected_packages.append(
                    AffectedPackage(
                        package=PackageURL(
                            type="huawei",
                            name=system_type
                        ),
                        affected_version_range=VersionRange.from_string(f"vers:generic/={version_number}") 
                    )
                )
            if not affected_packages:
                return None
            severity = VulnerabilitySeverity(
                system=GENERIC,
                value=data["severity"].lower()
            )
            references = [
                Reference(
                    reference_id=data["cve_id"],
                    url=f"https://nvd.nist.gov/vuln/detail/{data['cve_id']}",
                    severities=[severity],
                )
            ]
            if data.get("is_huawei"):
                summary = "\n".join(filter(None, [data.get("description"), data.get("impact")]))
            else:
                summary = f"Third-party vulnerability affecting {''.join(data['affected_versions'].split())}"
            return AdvisoryData(
                summary=summary if summary else f"Security update for {data['cve_id']}", 
                aliases=[data["cve_id"]],
                affected_packages=affected_packages,
                references=references,
                date_published=None,  
                url=f"{self.url}2024/9/"  
            )
        except Exception as e:
            self.log(f"Failed to process advisory {data.get('cve_id')}: {e}", logging.ERROR)
            return None
