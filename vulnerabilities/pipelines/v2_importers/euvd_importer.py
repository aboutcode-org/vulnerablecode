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
import time
from datetime import datetime
from http import HTTPStatus
from typing import Iterable

import requests
from dateutil import parser as dateparser

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import SCORING_SYSTEMS

logger = logging.getLogger(__name__)


class EUVDImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    EUVD (EU Vulnerability Database) Importer Pipeline

    This pipeline imports security advisories from the European Union Vulnerability Database (EUVD).
    """

    pipeline_id = "euvd_importer_v2"
    spdx_license_expression = "LicenseRef-scancode-other-permissive"
    license_url = "https://www.enisa.europa.eu/about-enisa/legal-notice/"
    url = "https://euvdservices.enisa.europa.eu/api/search"

    def __init__(self):
        super().__init__()
        self._cached_data = None

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)

    def fetch_data(self):
        # Return cached data if already fetched
        if self._cached_data is not None:
            logger.info(f"Using cached data: {len(self._cached_data)} items")
            return self._cached_data

        headers = {"User-Agent": "VulnerableCode"}
        all_items = []
        page = 0
        size = 100
        max_retries = 100

        logger.info(f"Fetching data from EUVD API: {self.url}")

        while True:

            retry_count = 0
            success = False

            while retry_count < max_retries and not success:
                try:
                    params = {"size": size, "page": page}
                    response = requests.get(self.url, headers=headers, params=params, timeout=30)

                    if response.status_code != HTTPStatus.OK:
                        logger.error(f"API returned status {response.status_code} for page {page}")
                        retry_count += 1
                        if retry_count < max_retries:
                            sleep_time = min(10 * (2 ** min(retry_count - 1, 5)), 60)
                            logger.info(
                                f"Retrying page {page} in {sleep_time}s (attempt {retry_count}/{max_retries})"
                            )
                            time.sleep(sleep_time)
                            continue
                        else:
                            logger.error(f"Max retries reached for page {page}")
                            return all_items

                    data = response.json()
                    items = data.get("items", [])

                    if not items:
                        logger.info(f"No items in response for page {page}; stopping fetch.")
                        logger.info(
                            f"Fetch completed successfully. Total items collected: {len(all_items)}"
                        )

                        # Cache the fetched data for reuse
                        self._cached_data = all_items
                        logger.info(f"Cached {len(all_items)} items for reuse")

                        return all_items

                    all_items.extend(items)
                    logger.info(
                        f"Fetched page {page}: {len(items)} items (total: {len(all_items)})"
                    )
                    success = True
                    page += 1

                except requests.exceptions.Timeout as e:
                    retry_count += 1
                    if retry_count < max_retries:
                        logger.warning(
                            f"Timeout on page {page}: {e}. Retrying in 10s (attempt {retry_count}/{max_retries})"
                        )
                        time.sleep(10)
                    else:
                        logger.error(f"Max retries reached for page {page} after timeout")
                        return all_items

                except Exception as e:
                    retry_count += 1
                    if retry_count < max_retries:
                        logger.error(
                            f"Error fetching page {page}: {e}. Retrying in 10s (attempt {retry_count}/{max_retries})"
                        )
                        time.sleep(10)
                    else:
                        logger.error(f"Max retries reached for page {page}")
                        return all_items

    def advisories_count(self) -> int:
        return len(self.fetch_data())

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        for raw_data in self.fetch_data():
            try:
                advisory = self.parse_advisory(raw_data)
                if advisory:
                    yield advisory
            except Exception as e:
                logger.error(f"Failed to parse advisory: {e}")
                logger.debug(f"Raw data: {raw_data}")
                continue

    def parse_advisory(self, raw_data: dict) -> AdvisoryData:
        advisory_id = raw_data.get("id", "")

        aliases = [advisory_id] if advisory_id else []
        aliases_str = raw_data.get("aliases", "")
        if aliases_str:
            cve_aliases = [alias.strip() for alias in aliases_str.split("\n") if alias.strip()]
            aliases.extend(cve_aliases)

        summary = raw_data.get("description", "")

        date_published = None
        date_str = raw_data.get("datePublished", "")
        if date_str:
            try:
                date_published = dateparser.parse(date_str)
                if date_published and date_published.tzinfo is None:
                    date_published = date_published.replace(
                        tzinfo=datetime.now().astimezone().tzinfo
                    )
            except Exception as e:
                logger.warning(f"Failed to parse date '{date_str}': {e}")

        references = []
        references_str = raw_data.get("references", "")
        if references_str:
            urls = [url.strip() for url in references_str.split("\n") if url.strip()]
            for url in urls:
                references.append(ReferenceV2(url=url))

        if advisory_id:
            advisory_url = f"https://euvd.enisa.europa.eu/vulnerability/{advisory_id}"
            references.append(ReferenceV2(url=advisory_url))

        severities = []
        base_score = raw_data.get("baseScore")
        base_score_version = raw_data.get("baseScoreVersion")
        base_score_vector = raw_data.get("baseScoreVector")

        if base_score and base_score_version:
            scoring_system = self.get_scoring_system(base_score_version)
            if scoring_system:
                severity = VulnerabilitySeverity(
                    system=scoring_system,
                    value=str(base_score),
                    scoring_elements=base_score_vector or "",
                )
                severities.append(severity)

        return AdvisoryData(
            advisory_id=advisory_id,
            aliases=aliases,
            summary=summary,
            references_v2=references,
            affected_packages=[],
            date_published=date_published,
            url=advisory_url if advisory_id else "",
            severities=severities,
            original_advisory_text=json.dumps(raw_data, indent=2, ensure_ascii=False),
        )

    @staticmethod
    def get_scoring_system(version: str):
        version_map = {
            "4.0": "cvssv4",
            "3.1": "cvssv3.1",
            "3.0": "cvssv3",
            "2.0": "cvssv2",
        }
        system_key = version_map.get(version)
        if system_key:
            return SCORING_SYSTEMS.get(system_key)
        logger.warning(f"Unknown CVSS version: {version}")
        return None
