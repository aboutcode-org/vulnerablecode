import logging
from datetime import datetime
from datetime import timezone
from typing import Iterable

import requests
from packageurl import PackageURL
from univers.version_range import NginxVersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import SCORING_SYSTEMS

logger = logging.getLogger(__name__)

class CurlImporter(Importer):

    spdx_license_expression = "MIT"
    license_url = "https://github.com/curl/curl-www/blob/master/LICENSE"
    repo_url = "https://github.com/curl/curl-www/"
    importer_name = "Curl Importer"
    api_url = "https://curl.se/docs/vuln.json"

    def get_response(self):
        response = requests.get(self.api_url)
        if response.status_code == 200:
            return response.json()
        raise Exception(
            f"Failed to fetch data from {self.api_url} with status code: {response.status_code!r}"
        )
    
    def advisory_data(self) -> Iterable[AdvisoryData]:

        raw_data = self.get_response()
        for data in raw_data:
            cve_id = data["aliases"]
            if not cve_id.startswith("CVE"):
                logger.error(f"Invalid CVE ID: {cve_id} in package {data['database_specific']['package']}")
                continue
            yield parse_advisory_data(data)

# Single dictionary is coming from the list of dictionaries in the input of below func.
def parse_advisory_data(raw_data) -> AdvisoryData:

    purl = PackageURL(type="curl", name="curl")
    # add range of raw data accordingly as f string using first and last value of the list.
    affected_version_range = NginxVersionRange.from_native(raw_data["vulnerable"])

    fixed_version = SemverVersion(raw_data["affected"][0]["ranges"][0]["events"][1]["fixed"])
    affected_package = AffectedPackage(
        package=purl, affected_version_range = affected_version_range, fixed_version=fixed_version
    )

    severity = VulnerabilitySeverity(
        system=SCORING_SYSTEMS["generic_textual"], value=raw_data["database_specific"]["severity"]
    )
    references = [Reference(url=raw_data["database_specific"]["www"], severities=[severity])]
    date_published = datetime.strptime(raw_data["published"], "%d-%m-%Y %Z").replace(
        tzinfo=timezone.utc
    )

    return AdvisoryData(
        aliases=[raw_data["aliases"]],
        summary=raw_data["summary"],
        affected_packages=[affected_package],# under progress
        references=references,
        date_published=date_published,
        url = raw_data["database_specific"]["URL"]
    )