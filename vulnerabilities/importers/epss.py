#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import csv
import gzip
import logging
import urllib.request
from datetime import datetime
from typing import Iterable

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity

logger = logging.getLogger(__name__)


class EPSSImporter(Importer):
    """Exploit Prediction Scoring System (EPSS) Importer"""

    advisory_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    spdx_license_expression = "unknown"
    importer_name = "EPSS Importer"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        response = urllib.request.urlopen(self.advisory_url)
        with gzip.open(response, "rb") as f:
            lines = [l.decode("utf-8") for l in f.readlines()]

        epss_reader = csv.reader(lines)
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

            references = Reference(
                url=f"https://api.first.org/data/v1/epss?cve={cve}",
                severities=[severity],
            )

            yield AdvisoryData(
                aliases=[cve],
                references=[references],
                url=self.advisory_url,
            )
