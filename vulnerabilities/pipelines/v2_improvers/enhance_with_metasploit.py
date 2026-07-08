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
import saneyaml
from aboutcode.pipeline import LoopProgress
from dateutil import parser as dateparser

from vulnerabilities.models import AdvisoryExploit
from vulnerabilities.models import PipelineSchedule
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.utils import build_alias_to_advisory_map


class MetasploitImproverPipeline(VulnerableCodePipeline):
    """
    Metasploit Exploits Pipeline: Retrieve Metasploit data, iterate through it to identify vulnerabilities
    by their associated aliases, and create or update the corresponding Exploit instances.
    """

    pipeline_id = "enhance_with_metasploit_v2"
    spdx_license_expression = "BSD-3-clause"

    # Run pipeline every 30 minutes.
    run_interval = 30
    run_priority = PipelineSchedule.ExecutionPriority.HIGH

    @classmethod
    def steps(cls):
        return (
            cls.fetch_exploits,
            cls.add_advisory_exploits,
        )

    def fetch_exploits(self):
        url = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
        self.log(f"Fetching {url}")
        try:
            response = requests.get(url)
            response.raise_for_status()
        except requests.exceptions.HTTPError as http_err:
            self.log(
                f"Failed to fetch the Metasploit Exploits: {url} with error {http_err!r}:\n{traceback_format_exc()}",
                level=logging.ERROR,
            )
            raise

        self.metasploit_data = response.json()

    def add_advisory_exploits(self):
        fetched_exploit_count = len(self.metasploit_data)
        self.log(f"Enhancing the vulnerability with {fetched_exploit_count:,d} exploit records")
        progress = LoopProgress(total_iterations=fetched_exploit_count, logger=self.log)

        all_references = set()

        for record in self.metasploit_data.values():
            for ref in record.get("references", []):
                if not ref.startswith("OSVDB") and not ref.startswith("URL-"):
                    all_references.add(ref)

        reference_to_advisories = build_alias_to_advisory_map(all_references)

        exploits = []
        seen = set()

        for record in progress.iter(self.metasploit_data.values()):
            description = record.get("description", "")
            notes = record.get("notes", {})
            platform = record.get("platform")

            source_url = ""
            if path := record.get("path"):
                source_url = f"https://github.com/rapid7/metasploit-framework/tree/master{path}"
            source_date_published = None

            if disclosure_date := record.get("disclosure_date"):
                try:
                    source_date_published = dateparser.parse(disclosure_date).date()
                except ValueError as e:
                    self.log(
                        f"Error while parsing date {disclosure_date} with error {e!r}:\n{traceback_format_exc()}",
                        level=logging.ERROR,
                    )
            refs = [
                ref
                for ref in record.get("references", [])
                if not ref.startswith("OSVDB") and not ref.startswith("URL-")
            ]

            record_id = record.get("path")

            if not record_id:
                continue

            for ref in refs:
                for advisory in reference_to_advisories.get(ref, ()):

                    key = (
                        advisory.id,
                        record_id,
                    )

                    if key in seen:
                        continue

                    seen.add(key)

                    exploits.append(
                        AdvisoryExploit(
                            advisory=advisory,
                            data_source="Metasploit",
                            record_id=record_id,
                            description=description,
                            notes=saneyaml.dump(notes),
                            source_date_published=source_date_published,
                            platform=platform,
                            source_url=source_url,
                        )
                    )

        AdvisoryExploit.objects.bulk_create(
            exploits,
            update_conflicts=True,
            unique_fields=[
                "advisory",
                "data_source",
                "record_id",
            ],
            update_fields=[
                "description",
                "notes",
                "source_date_published",
                "platform",
                "source_url",
            ],
            batch_size=1000,
        )
