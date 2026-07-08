#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from traceback import format_exc as traceback_format_exc

import requests
from aboutcode.pipeline import LoopProgress

from vulnerabilities.models import AdvisoryExploit
from vulnerabilities.models import PipelineSchedule
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.utils import build_alias_to_advisory_map


class VulnerabilityKevPipeline(VulnerableCodePipeline):
    """
    Known Exploited Vulnerabilities Pipeline: Retrieve KEV data, iterate through it to identify vulnerabilities
    by their associated aliases, and create or update the corresponding Exploit instances.
    """

    pipeline_id = "enhance_with_kev_v2"
    license_expression = None

    # Run pipeline every 30 minutes.
    run_interval = 30
    run_priority = PipelineSchedule.ExecutionPriority.HIGH

    @classmethod
    def steps(cls):
        return (
            cls.fetch_exploits,
            cls.add_exploits,
        )

    def fetch_exploits(self):
        kev_url = "https://raw.githubusercontent.com/aboutcode-org/aboutcode-mirror-kev/refs/heads/main/known_exploited_vulnerabilities.json"
        self.log(f"Fetching {kev_url}")

        try:
            response = requests.get(kev_url)
            response.raise_for_status()
        except requests.exceptions.HTTPError as http_err:
            self.log(
                f"Failed to fetch the KEV Exploits: {kev_url} with error {http_err!r}:\n{traceback_format_exc()}",
                level=logging.ERROR,
            )
            raise
        self.kev_data = response.json()

    def add_exploits(self):
        fetched_exploit_count = self.kev_data.get("count")
        self.log(f"Enhancing the vulnerability with {fetched_exploit_count:,d} exploit records")
        progress = LoopProgress(total_iterations=fetched_exploit_count, logger=self.log)
        cve_ids = {
            record["cveID"] for record in self.kev_data["vulnerabilities"] if record.get("cveID")
        }

        cve_to_advisories = build_alias_to_advisory_map(cve_ids)

        exploits = []

        advisories_seen_multiple_times = set()

        for record in progress.iter(self.kev_data["vulnerabilities"]):
            cve_id = record.get("cveID")

            if not cve_id:
                continue

            for advisory in cve_to_advisories.get(cve_id, []):
                if (advisory.avid, cve_id) in advisories_seen_multiple_times:
                    continue
                advisories_seen_multiple_times.add((advisory.avid, cve_id))
                exploits.append(
                    AdvisoryExploit(
                        advisory=advisory,
                        record_id=cve_id,
                        data_source="KEV",
                        description=record["shortDescription"],
                        date_added=record["dateAdded"],
                        required_action=record["requiredAction"],
                        due_date=record["dueDate"],
                        notes=record["notes"],
                        known_ransomware_campaign_use=(
                            record["knownRansomwareCampaignUse"] == "Known"
                        ),
                    )
                )
        if not exploits:
            return

        AdvisoryExploit.objects.bulk_create(
            exploits,
            update_conflicts=True,
            unique_fields=["advisory", "data_source", "record_id"],
            update_fields=[
                "description",
                "date_added",
                "required_action",
                "due_date",
                "notes",
                "known_ransomware_campaign_use",
            ],
            batch_size=1000,
        )
