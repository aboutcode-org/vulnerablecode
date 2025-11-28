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
import math
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
        if self._cached_data is not None:
            logger.info(f"Using cached data: {len(self._cached_data)} items")
            return self._cached_data

        all_items = []
        size = 100
        max_retries = 2

        logger.info(f"Fetching data from EUVD API: {self.url}")

        total_count = self._fetch_total_count(size, max_retries)
        if total_count is None:
            logger.error("Failed to fetch total count from API")
            return all_items

        total_pages = math.ceil(total_count / size)
        logger.info(f"Total advisories: {total_count}, Total pages: {total_pages}")

        first_page_data = self._fetch_page(0, size, max_retries)
        if first_page_data:
            all_items.extend(first_page_data)
            logger.info(f"Fetched page 0: {len(first_page_data)} items (total: {len(all_items)})")

        for page in range(1, total_pages):
            page_data = self._fetch_page(page, size, max_retries)
            if page_data is None:
                logger.warning(f"Skipping page {page} after failed retries")
                continue

            if not page_data:
                logger.info(f"No items in response for page {page}; stopping fetch.")
                break

            all_items.extend(page_data)
            logger.info(f"Fetched page {page}: {len(page_data)} items (total: {len(all_items)})")

        logger.info(f"Fetch completed successfully. Total items collected: {len(all_items)}")

        self._cached_data = all_items
        logger.info(f"Cached {len(all_items)} items for reuse")

        return all_items

    def _make_request_with_retry(self, params, max_retries, context):
        headers = {"User-Agent": "VulnerableCode"}

        for attempt in range(max_retries):
            try:
                response = requests.get(self.url, headers=headers, params=params, timeout=30)

                if response.status_code != HTTPStatus.OK:
                    logger.error(f"API returned status {response.status_code} for {context}")
                    if attempt < max_retries - 1:
                        logger.info(f"Retrying {context} (attempt {attempt + 1}/{max_retries})")
                        time.sleep(3)
                        continue
                    return None

                return response.json()

            except requests.exceptions.Timeout:
                logger.warning(f"Timeout on {context} (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(3)
                    continue
                return None

            except requests.exceptions.RequestException as e:
                logger.error(
                    f"Network error on {context}: {e} (attempt {attempt + 1}/{max_retries})"
                )
                if attempt < max_retries - 1:
                    time.sleep(3)
                    continue
                return None

            except (ValueError, KeyError) as e:
                logger.error(f"Error parsing response for {context}: {e}")
                return None

        return None

    def _fetch_total_count(self, size, max_retries):
        """Fetch the total count of advisories from the API."""
        params = {"size": size, "page": 0}
        data = self._make_request_with_retry(params, max_retries, "total count")

        if data is None:
            return None

        total = data.get("total")
        if total is None:
            logger.error("No 'total' field in API response")

        return total

    def _fetch_page(self, page, size, max_retries):
        """Fetch a single page of advisories from the API."""
        params = {"size": size, "page": page}
        data = self._make_request_with_retry(params, max_retries, f"page {page}")

        if data is None:
            return None

        return data.get("items", [])

    def advisories_count(self) -> int:
        return len(self.fetch_data())

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        for raw_data in self.fetch_data():
            try:
                advisory = self.parse_advisory(raw_data)
                if advisory:
                    yield advisory
            except (ValueError, KeyError, TypeError) as e:
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
            except (ValueError, TypeError) as e:
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
