#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from datetime import datetime
from datetime import timezone
from typing import Iterable
from typing import Mapping

import requests
from packageurl import PackageURL
from univers.version_range import GenericVersionRange
from univers.versions import SemverVersion
from utils import fetch_response
from utils import get_item

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

    def fetch(self) -> Iterable[Mapping]:
        response = fetch_response(self.url)
        return response.json()

    def advisory_data(self) -> Iterable[AdvisoryData]:
        raw_data = self.fetch()
        for data in raw_data:
            cve_id = data.get("aliases") or []
            cve_id = cve_id[0] if len(cve_id) > 0 else None
            if not cve_id.startswith("CVE"):
                package = data.get("database_specific").get("package")
                logger.error(f"Invalid CVE ID: {cve_id} in package {package}")
                continue
            yield parse_advisory_data(data)


def parse_advisory_data(raw_data) -> AdvisoryData:

    d1 = get_item(raw_data, "affected")[0] if len(get_item(raw_data, "affected")) > 0 else []
    d2 = get_item(d1, "ranges")[0] if len(get_item(d1, "ranges")) > 0 else []
    d3 = get_item(d2, "events")[1] if len(get_item(d2, "events")) > 1 else {}

    fixed_version = SemverVersion(d3.get("fixed") or "")
    purl = PackageURL(type="generic", namespace="curl.se", name="curl")
    affected_version_range = GenericVersionRange.from_versions(
        raw_data.get("affected")[0].get("versions") or []
    )

    affected_package = AffectedPackage(
        package=purl, affected_version_range=affected_version_range, fixed_version=fixed_version
    )

    database_specific = raw_data.get("database_specific") or {}
    severity = VulnerabilitySeverity(
        system=SCORING_SYSTEMS["generic_textual"], value=database_specific.get("severity", "")
    )

    references = [Reference(url=database_specific.get("www") or "", severities=[severity])]
    date_published = datetime.strptime(raw_data.get("published") or "", "%d-%m-%Y %Z").replace(
        tzinfo=timezone.utc
    )

    return AdvisoryData(
        aliases=raw_data.get("aliases") or [],
        summary=raw_data.get("summary") or "",
        affected_packages=[affected_package],
        references=references,
        date_published=date_published,
        url=raw_data.get("database_specific", {}).get("URL", ""),
    )
