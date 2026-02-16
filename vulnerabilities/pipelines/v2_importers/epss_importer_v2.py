#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import csv
import gzip
import logging
import urllib.request
from datetime import datetime
from typing import Iterable

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2

logger = logging.getLogger(__name__)


class EPSSImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Exploit Prediction Scoring System (EPSS) Importer"""

    advisory_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    pipeline_id = "epss_importer_v2"
    spdx_license_expression = "unknown"
    importer_name = "EPSS Importer"

    precedence = 200

    def advisories_count(self):
        return len(self.lines)

    @classmethod
    def steps(cls):
        return (
            cls.fetch_db,
            cls.collect_and_store_advisories,
        )

    def fetch_db(self):
        logger.info(f"Fetching EPSS database from {self.advisory_url}")
        response = urllib.request.urlopen(self.advisory_url)
        with gzip.open(response, "rb") as f:
            self.lines = [l.decode("utf-8") for l in f.readlines()]

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        if not self.lines:
            logger.error("No EPSS data loaded")
            raise ValueError("EPSS data is empty")

        epss_reader = csv.reader(self.lines)
        model_version, score_date = next(
            epss_reader
        )  # score_date='score_date:2024-05-19T00:00:00+0000'
        published_at = datetime.strptime(score_date[11::], "%Y-%m-%dT%H:%M:%S%z")

        next(epss_reader)  # skip the header row
        for epss_row in epss_reader:
            cve, score, percentile = epss_row

            if not cve or not score or not percentile:
                logger.error(f"Invalid epss row: {epss_row}")
                continue

            severity = VulnerabilitySeverity(
                system=severity_systems.EPSS,
                value=score,
                scoring_elements=percentile,
                published_at=published_at,
            )

            references = ReferenceV2(
                url=f"https://api.first.org/data/v1/epss?cve={cve}",
            )

            yield AdvisoryDataV2(
                advisory_id=cve,
                severities=[severity],
                references=[references],
                url=self.advisory_url,
            )
