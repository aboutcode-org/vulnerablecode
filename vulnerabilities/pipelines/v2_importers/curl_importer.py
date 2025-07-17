#
# Copyright (c) nexB Inc. and others. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

import json
import logging
from datetime import datetime
from datetime import timezone
from typing import Iterable

from cwe2.database import Database
from packageurl import PackageURL
from univers.version_range import GenericVersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import fetch_response
from vulnerabilities.utils import get_cwe_id
from vulnerabilities.utils import get_item

logger = logging.getLogger(__name__)


class CurlImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Pipeline-based importer for curl advisories from curl.se.
    """

    pipeline_id = "curl_importer_v2"
    spdx_license_expression = "curl"
    license_url = "https://curl.se/docs/copyright.html"
    repo_url = "https://github.com/curl/curl-www/"
    url = "https://curl.se/docs/vuln.json"
    unfurl_version_ranges = True

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)

    def fetch_data(self):
        return fetch_response(self.url).json()

    def advisories_count(self) -> int:
        return len(self.fetch_data())

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        for entry in self.fetch_data():
            cve_id = entry.get("aliases") or []
            cve_id = cve_id[0] if cve_id else None
            if not cve_id or not cve_id.startswith("CVE"):
                package = get_item(entry, "database_specific", "package")
                logger.error(f"Invalid CVE ID: {cve_id} in package {package}")
                continue
            yield parse_curl_advisory(entry)


def parse_curl_advisory(raw_data) -> AdvisoryData:
    """
    Parse advisory data from raw JSON data and return an AdvisoryData object.

    Args:
        raw_data (dict): Raw JSON data containing advisory information.

    Returns:
        AdvisoryData: Parsed advisory data as an AdvisoryData object.
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
        package=purl,
        affected_version_range=affected_version_range,
        fixed_version=fixed_version,
    )

    database_specific = raw_data.get("database_specific") or {}

    references = []
    www_url = database_specific.get("www")
    issue_url = database_specific.get("issue")
    json_url = database_specific.get("URL")

    if www_url:
        references.append(ReferenceV2(url=www_url))
    if issue_url:
        references.append(ReferenceV2(url=issue_url))
    severity = VulnerabilitySeverity(
        system=SCORING_SYSTEMS["cvssv3.1"], value=database_specific.get("severity", ""), url=www_url
    )

    published = raw_data.get("published", "")
    date_published = (
        datetime.strptime(published, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        if published
        else None
    )

    weaknesses = get_cwe_from_curl_advisory(raw_data)

    aliases = raw_data.get("aliases", [])
    advisory_id = raw_data.get("id") or ""

    if advisory_id in aliases:
        aliases.remove(advisory_id)

    return AdvisoryData(
        advisory_id=advisory_id,
        aliases=aliases,
        summary=raw_data.get("summary") or "",
        affected_packages=[affected_package],
        references_v2=references,
        date_published=date_published,
        weaknesses=weaknesses,
        url=json_url,
        severities=[severity],
        original_advisory_text=json.dumps(raw_data, indent=2, ensure_ascii=False),
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
        try:
            cwe_id = get_cwe_id(cwe_string)
            db.get(cwe_id)  # validate CWE exists
            weaknesses.append(cwe_id)
        except Exception:
            logger.error(f"Invalid CWE id: {cwe_string}")
    return weaknesses
