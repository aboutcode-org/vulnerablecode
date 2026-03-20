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
from typing import Iterable

import dateparser
import requests

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import SCORING_SYSTEMS

logger = logging.getLogger(__name__)

COLLABORA_URL = "https://api.github.com/repos/CollaboraOnline/online/security-advisories"


class CollaboraImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Collect Collabora Online security advisories from the GitHub Security Advisory API."""

    pipeline_id = "collabora_importer"
    spdx_license_expression = "LicenseRef-scancode-proprietary-license"
    license_url = "https://github.com/CollaboraOnline/online/security/advisories"
    precedence = 200

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)

    def advisories_count(self) -> int:
        return 0

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        url = COLLABORA_URL
        params = {"state": "published", "per_page": 100}
        while url:
            try:
                resp = requests.get(url, params=params, timeout=30)
                resp.raise_for_status()
            except Exception as e:
                logger.error("Failed to fetch Collabora advisories from %s: %s", url, e)
                break
            for item in resp.json():
                advisory = parse_advisory(item)
                if advisory:
                    yield advisory
            # cursor is already embedded in the next URL
            url = resp.links.get("next", {}).get("url")
            params = None


def parse_advisory(data: dict):
    """Parse a GitHub security advisory object; return None if the GHSA ID is missing."""
    ghsa_id = data.get("ghsa_id") or ""
    if not ghsa_id:
        return None

    cve_id = data.get("cve_id") or ""
    aliases = [cve_id] if cve_id else []

    summary = data.get("summary") or ""
    html_url = data.get("html_url") or ""
    references = [ReferenceV2(url=html_url)] if html_url else []

    date_published = None
    published_at = data.get("published_at") or ""
    if published_at:
        date_published = dateparser.parse(published_at)
        if date_published is None:
            logger.warning("Could not parse date %r for %s", published_at, ghsa_id)

    severities = []
    cvss_v3 = (data.get("cvss_severities") or {}).get("cvss_v3") or {}
    cvss_vector = cvss_v3.get("vector_string") or ""
    cvss_score = cvss_v3.get("score")
    if cvss_vector and cvss_score:
        system = (
            SCORING_SYSTEMS["cvssv3.1"]
            if cvss_vector.startswith("CVSS:3.1/")
            else SCORING_SYSTEMS["cvssv3"]
        )
        severities.append(
            VulnerabilitySeverity(
                system=system,
                value=str(cvss_score),
                scoring_elements=cvss_vector,
            )
        )

    weaknesses = []
    for cwe_str in data.get("cwe_ids") or []:
        # cwe_ids entries are like "CWE-79"; extract the integer part
        suffix = cwe_str[4:] if cwe_str.upper().startswith("CWE-") else ""
        if suffix.isdigit():
            weaknesses.append(int(suffix))

    return AdvisoryDataV2(
        advisory_id=ghsa_id,
        aliases=aliases,
        summary=summary,
        affected_packages=[],
        references=references,
        date_published=date_published,
        severities=severities,
        weaknesses=weaknesses,
        url=html_url,
        original_advisory_text=json.dumps(data, indent=2, ensure_ascii=False),
    )
