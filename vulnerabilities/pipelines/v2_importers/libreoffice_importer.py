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
from typing import Iterable

import dateparser
import requests

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import get_cwe_id

logger = logging.getLogger(__name__)

ADVISORIES_URL = "https://www.libreoffice.org/about-us/security/advisories/"
CVE_API_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"

CVSS_KEY_MAP = {
    "cvssV4_0": SCORING_SYSTEMS["cvssv4"],
    "cvssV3_1": SCORING_SYSTEMS["cvssv3.1"],
    "cvssV3_0": SCORING_SYSTEMS["cvssv3"],
    "cvssV2_0": SCORING_SYSTEMS["cvssv2"],
}


class LibreOfficeImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Collect LibreOffice security advisories via the CVE API."""

    pipeline_id = "libreoffice_importer"
    spdx_license_expression = "LicenseRef-scancode-proprietary-license"
    license_url = "https://www.libreoffice.org/about-us/security/"
    precedence = 200

    @classmethod
    def steps(cls):
        return (
            cls.fetch,
            cls.collect_and_store_advisories,
        )

    def fetch(self):
        self.log(f"Fetch `{ADVISORIES_URL}`")
        resp = requests.get(ADVISORIES_URL, timeout=30)
        resp.raise_for_status()
        self.cve_ids = parse_cve_ids(resp.text)

    def advisories_count(self):
        return len(self.cve_ids)

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        for cve_id in self.cve_ids:
            url = CVE_API_URL.format(cve_id=cve_id)
            try:
                resp = requests.get(url, timeout=30)
                resp.raise_for_status()
            except Exception as e:
                logger.error("Failed to fetch CVE API for %s: %s", cve_id, e)
                continue
            advisory = parse_cve_advisory(resp.json(), cve_id)
            if advisory:
                yield advisory


def parse_cve_ids(html: str) -> list:
    """Return deduplicated CVE IDs from the LibreOffice advisories listing page."""
    return list(dict.fromkeys(re.findall(r"CVE-\d{4}-\d+", html)))


def parse_cve_advisory(data: dict, cve_id: str):
    """Parse a CVE 5.0 JSON record from cveawg.mitre.org; return None if CVE ID is absent."""
    cve_metadata = data.get("cveMetadata") or {}
    advisory_id = cve_metadata.get("cveId") or cve_id
    if not advisory_id:
        return None

    date_published = None
    raw_date = cve_metadata.get("datePublished") or ""
    if raw_date:
        date_published = dateparser.parse(
            raw_date,
            settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True, "TO_TIMEZONE": "UTC"},
        )
        if date_published is None:
            logger.warning("Could not parse date %r for %s", raw_date, advisory_id)

    cna = (data.get("containers") or {}).get("cna") or {}

    summary = ""
    for desc in cna.get("descriptions") or []:
        if desc.get("lang") in ("en", "en-US"):
            summary = desc.get("value") or ""
            break

    severities = []
    for metric in cna.get("metrics") or []:
        for key, system in CVSS_KEY_MAP.items():
            cvss = metric.get(key)
            if not cvss:
                continue
            vector = cvss.get("vectorString") or ""
            score = cvss.get("baseScore")
            if vector and score is not None:
                severities.append(
                    VulnerabilitySeverity(
                        system=system,
                        value=str(score),
                        scoring_elements=vector,
                    )
                )
            break

    weaknesses = []
    for problem_type in cna.get("problemTypes") or []:
        for desc in problem_type.get("descriptions") or []:
            cwe_str = desc.get("cweId") or ""
            if cwe_str.upper().startswith("CWE-"):
                try:
                    weaknesses.append(get_cwe_id(cwe_str))
                except Exception:
                    pass

    advisory_url = (
        f"https://www.libreoffice.org/about-us/security/advisories/{advisory_id.lower()}/"
    )
    references = []
    for ref in cna.get("references") or []:
        url = ref.get("url") or ""
        if url:
            references.append(ReferenceV2(url=url))

    return AdvisoryDataV2(
        advisory_id=advisory_id,
        aliases=[],
        summary=summary,
        affected_packages=[],
        references=references,
        date_published=date_published,
        weaknesses=weaknesses,
        severities=severities,
        url=advisory_url,
        original_advisory_text=json.dumps(data, indent=2, ensure_ascii=False),
    )
