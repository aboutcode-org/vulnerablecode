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
import urllib.request
from datetime import datetime
from datetime import timedelta
from decimal import Decimal

from django.utils import timezone

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import EPSSScore
from vulnerabilities.models import PipelineSchedule
from vulnerabilities.pipelines import VulnerableCodePipeline


class EPSSPipeline(VulnerableCodePipeline):
    """
    Exploit Prediction Scoring System (EPSS) Pipeline.

    Downloads the latest daily EPSS CSV and bulk-inserts scores into EPSSScore model. Prunes scores older than the retention window.
    """

    pipeline_id = "epss_pipeline"
    advisory_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    spdx_license_expression = "unknown"

    # Run pipeline every day.
    run_interval = 1440
    run_priority = PipelineSchedule.ExecutionPriority.HIGH
    retention_days = 90  # Keep 90 days of EPSS scores
    batch_size = 10_000

    @classmethod
    def steps(cls):
        return (
            cls.fetch_and_bulk_load_scores,
            cls.prune_old_scores,
        )

    def fetch_and_bulk_load_scores(self):
        self.log(f"Fetching EPSS data from {self.advisory_url}")
        response = urllib.request.urlopen(self.advisory_url)

        with gzip.open(response, "rt", encoding="utf-8") as gzip_stream:
            epss_csv_reader = csv.reader(gzip_stream)

            # Extract date from metadata header
            _, date_header = next(epss_csv_reader)
            score_date = datetime.fromisoformat(date_header.removeprefix("score_date:")).date()

            # Skip column headers
            next(epss_csv_reader)

            scores_by_cve = {
                cve: (epss_score, percentile) for cve, epss_score, percentile in epss_csv_reader
            }

        self.log(f"Parsed {len(scores_by_cve):,d} EPSS scores for {score_date}.")

        # Map CVEs to ``AdvisoryAlias`` IDs and create any missing aliases
        cve_to_alias_id = dict(
            AdvisoryAlias.objects.filter(alias__in=scores_by_cve.keys()).values_list("alias", "id")
        )
        missing_cves = set(scores_by_cve) - set(cve_to_alias_id)
        if missing_cves:
            self.log(f"Creating {len(missing_cves):,d} new CVE records")
            new_aliases = [AdvisoryAlias(alias=cve) for cve in missing_cves]
            AdvisoryAlias.objects.bulk_create(
                new_aliases,
                batch_size=self.batch_size,
                ignore_conflicts=True,
            )
            cve_to_alias_id.update(
                AdvisoryAlias.objects.filter(alias__in=missing_cves).values_list("alias", "id")
            )

        # Mark previous days' scores as no longer latest ie ``is_latest=False``
        alias_ids = list(cve_to_alias_id.values())
        for i in range(0, len(alias_ids), self.batch_size):
            alias_id_batch = alias_ids[i : i + self.batch_size]
            EPSSScore.objects.filter(
                alias_id__in=alias_id_batch,
                date__lt=score_date,
                is_latest=True,
            ).update(is_latest=False)

        # Bulk insert today's scores as ``is_latest=True``
        scores = []
        for cve, (epss_score, percentile) in scores_by_cve.items():
            alias_id = cve_to_alias_id.get(cve)
            if alias_id:
                score = EPSSScore(
                    alias_id=alias_id,
                    date=score_date,
                    score=Decimal(epss_score),
                    percentile=Decimal(percentile),
                    is_latest=True,
                )
                scores.append(score)
        EPSSScore.objects.bulk_create(
            scores,
            batch_size=self.batch_size,
            update_conflicts=True,
            update_fields=["score", "percentile", "is_latest"],
            unique_fields=["alias", "date"],
        )

        self.log(f"Successfully inserted {len(scores):,d} EPSS scores for {score_date}")

    def prune_old_scores(self):
        """
        Delete EPSS score records older than ``retention_days``.
        """
        cutoff = timezone.now().date() - timedelta(days=self.retention_days)
        deleted_count, _ = EPSSScore.objects.filter(date__lt=cutoff).delete()
        self.log(
            f"Pruned {deleted_count:,d} EPSS records older than {cutoff} (retention: {self.retention_days} days)"
        )
