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
from vulnerabilities.severity_systems import GENERIC

logger = logging.getLogger(__name__)

ECLIPSE_API_URL = "https://api.eclipse.org/cve"


class EclipseImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Collect Eclipse Foundation security advisories via the Eclipse CVE API."""

    pipeline_id = "eclipse_importer"
    spdx_license_expression = "LicenseRef-scancode-proprietary-license"
    license_url = "https://www.eclipse.org/security/"
    precedence = 200

    @classmethod
    def steps(cls):
        return (
            cls.fetch,
            cls.collect_and_store_advisories,
        )

    def fetch(self):
        self.log(f"Fetch `{ECLIPSE_API_URL}`")
        resp = requests.get(ECLIPSE_API_URL, timeout=30)
        resp.raise_for_status()
        self.advisories_data = resp.json()

    def advisories_count(self):
        return len(self.advisories_data)

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        for entry in self.advisories_data:
            advisory = parse_advisory(entry)
            if advisory:
                yield advisory


def parse_advisory(entry: dict):
    advisory_id = entry.get("id") or ""
    if not advisory_id:
        return None

    date_published = None
    raw_date = entry.get("date_published") or ""
    if raw_date:
        date_published = dateparser.parse(
            raw_date,
            settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True, "TO_TIMEZONE": "UTC"},
        )
        if date_published is None:
            logger.warning("Could not parse date %r for %s", raw_date, advisory_id)

    summary_obj = entry.get("summary")
    summary = summary_obj.get("content") or "" if isinstance(summary_obj, dict) else ""

    references = []
    for url in [
        entry.get("live_link") or "",
        entry.get("request_link") or "",
        entry.get("cve_pull_request") or "",
    ]:
        if url:
            references.append(ReferenceV2(url=url))

    severities = []
    cvss = entry.get("cvss")
    if cvss is not None:
        severities.append(VulnerabilitySeverity(system=GENERIC, value=str(cvss)))

    advisory_url = entry.get("live_link") or ""

    return AdvisoryDataV2(
        advisory_id=advisory_id,
        aliases=[],
        summary=summary,
        affected_packages=[],
        references=references,
        date_published=date_published,
        weaknesses=[],
        severities=severities,
        url=advisory_url,
        original_advisory_text=json.dumps(entry, indent=2, ensure_ascii=False),
    )
