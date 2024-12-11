#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from datetime import datetime
from datetime import timezone
from typing import Iterable
from typing import Mapping

from cwe2.database import Database
from packageurl import PackageURL
from univers.version_range import GenericVersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import fetch_response
from vulnerabilities.utils import get_cwe_id
from vulnerabilities.utils import get_item

logger = logging.getLogger(__name__)


class CurlImporter(Importer):

    spdx_license_expression = "curl"
    license_url = "https://curl.se/docs/copyright.html"
    repo_url = "https://github.com/curl/curl-www/"
    importer_name = "Curl Importer"
    api_url = "https://curl.se/docs/vuln.json"

    def fetch(self) -> Iterable[Mapping]:
        response = fetch_response(self.api_url)
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
    """
    Parse advisory data from raw JSON data and return an AdvisoryData object.

    Args:
        raw_data (dict): Raw JSON data containing advisory information.

    Returns:
        AdvisoryData: Parsed advisory data as an AdvisoryData object.

    Example:
        >>> raw_data = {
        ...     "aliases": ["CVE-2024-2379"],
        ...     "summary": "QUIC certificate check bypass with wolfSSL",
        ...     "database_specific": {
        ...         "package": "curl",
        ...         "URL": "https://curl.se/docs/CVE-2024-2379.json",
        ...         "www": "https://curl.se/docs/CVE-2024-2379.html",
        ...         "issue": "https://hackerone.com/reports/2410774",
        ...         "severity": "Low",
        ...         "CWE": {
        ...             "id": "CWE-297",
        ...             "desc": "Improper Validation of Certificate with Host Mismatch"
        ...         },
        ...     },
        ...     "published": "2024-03-27T08:00:00.00Z",
        ...     "affected": [
        ...         {
        ...             "ranges": [
        ...                 {
        ...                     "type": "SEMVER",
        ...                     "events": [
        ...                         {"introduced": "8.6.0"},
        ...                         {"fixed": "8.7.0"}
        ...                     ]
        ...                 }
        ...             ],
        ...             "versions": ["8.6.0"]
        ...         }
        ...     ]
        ... }
        >>> parse_advisory_data(raw_data)
        AdvisoryData(aliases=['CVE-2024-2379'], summary='QUIC certificate check bypass with wolfSSL', affected_packages=[AffectedPackage(package=PackageURL(type='generic', namespace='curl.se', name='curl', version=None, qualifiers={}, subpath=None), affected_version_range=GenericVersionRange(constraints=(VersionConstraint(comparator='=', version=SemverVersion(string='8.6.0')),)), fixed_version=SemverVersion(string='8.7.0'))], references=[Reference(reference_id='', reference_type='', url='https://curl.se/docs/CVE-2024-2379.html', severities=[VulnerabilitySeverity(system=Cvssv3ScoringSystem(identifier='cvssv3.1', name='CVSSv3.1 Base Score', url='https://www.first.org/cvss/v3-1/', notes='CVSSv3.1 base score and vector'), value='Low', scoring_elements='', published_at=None)]), Reference(reference_id='', reference_type='', url='https://hackerone.com/reports/2410774', severities=[])], date_published=datetime.datetime(2024, 3, 27, 8, 0, tzinfo=datetime.timezone.utc), weaknesses=[297], url='https://curl.se/docs/CVE-2024-2379.json')
    """

    affected = get_item(raw_data, "affected")[0] if len(get_item(raw_data, "affected")) > 0 else []

    ranges = get_item(affected, "ranges")[0] if len(get_item(affected, "ranges")) > 0 else []
    events = get_item(ranges, "events")[1] if len(get_item(ranges, "events")) > 1 else {}
    version_type = get_item(ranges, "type") if get_item(ranges, "type") else ""
    fixed_version = events.get("fixed")
    if version_type == "SEMVER" and fixed_version:
        fixed_version = SemverVersion(fixed_version)

    purl = PackageURL(type="generic", namespace="curl.se", name="curl")
    versions = affected.get("versions") or []
    affected_version_range = GenericVersionRange.from_versions(versions)

    affected_package = AffectedPackage(
        package=purl, affected_version_range=affected_version_range, fixed_version=fixed_version
    )

    database_specific = raw_data.get("database_specific") or {}
    severity = VulnerabilitySeverity(
        system=SCORING_SYSTEMS["cvssv3.1"], value=database_specific.get("severity", "")
    )

    references = []
    ref_www = database_specific.get("www") or ""
    ref_issue = database_specific.get("issue") or ""
    if ref_www:
        references.append(Reference(url=ref_www, severities=[severity]))
    if ref_issue:
        references.append(Reference(url=ref_issue))

    date_published = datetime.strptime(
        raw_data.get("published") or "", "%Y-%m-%dT%H:%M:%S.%fZ"
    ).replace(tzinfo=timezone.utc)
    weaknesses = get_cwe_from_curl_advisory(raw_data)

    return AdvisoryData(
        aliases=raw_data.get("aliases") or [],
        summary=raw_data.get("summary") or "",
        affected_packages=[affected_package],
        references=references,
        date_published=date_published,
        weaknesses=weaknesses,
        url=raw_data.get("database_specific", {}).get("URL", ""),
    )


def get_cwe_from_curl_advisory(raw_data):
    """
    Extracts CWE IDs from the given raw_data and returns a list of CWE IDs.

        >>> get_cwe_from_curl_advisory({"database_specific": {"CWE": {"id": "CWE-333"}}})
        [333]
        >>> get_cwe_from_curl_advisory({"database_specific": {"CWE": {"id": ""}}})
        []
    """
    weaknesses = []
    db = Database()
    cwe_string = get_item(raw_data, "database_specific", "CWE", "id") or ""

    if cwe_string:
        cwe_id = get_cwe_id(cwe_string)
        try:
            db.get(cwe_id)
            weaknesses.append(cwe_id)
        except Exception:
            logger.error("Invalid CWE id")
    return weaknesses
