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

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryExploit
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.pipelines import VulnerableCodePipeline

from django.conf import settings


class MetasploitImproverPipeline(VulnerableCodePipeline):
    """
    Metasploit Exploits Pipeline: Retrieve Metasploit data, iterate through it to identify vulnerabilities
    by their associated aliases, and create or update the corresponding Exploit instances.
    """

    pipeline_id = "enhance_with_metasploit_v2"
    spdx_license_expression = "BSD-3-clause"

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
            response = requests.get(
                url,
                headers={'User-Agent': settings.VC_USER_AGENT}
            )
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

        vulnerability_exploit_count = 0
        progress = LoopProgress(total_iterations=fetched_exploit_count, logger=self.log)
        for _, record in progress.iter(self.metasploit_data.items()):
            vulnerability_exploit_count += add_advisory_exploit(
                record=record,
                logger=self.log,
            )
        self.log(f"Successfully added {vulnerability_exploit_count:,d} vulnerability exploit")


def add_advisory_exploit(record, logger):
    advisories = set()
    references = record.get("references", [])

    interesting_references = [
        ref for ref in references if not ref.startswith("OSVDB") and not ref.startswith("URL-")
    ]

    if not interesting_references:
        return 0

    for ref in interesting_references:
        try:
            if alias := AdvisoryAlias.objects.get(alias=ref):
                for adv in alias.advisories.all():
                    advisories.add(adv)
            else:
                advs = AdvisoryV2.objects.filter(advisory_id=ref)
                for adv in advs:
                    advisories.add(adv)
        except AdvisoryAlias.DoesNotExist:
            continue

    if not advisories:
        logger(f"No advisories found for aliases {interesting_references}")
        return 0

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
            logger(
                f"Error while parsing date {disclosure_date} with error {e!r}:\n{traceback_format_exc()}",
                level=logging.ERROR,
            )

    for advisory in advisories:
        AdvisoryExploit.objects.update_or_create(
            advisory=advisory,
            data_source="Metasploit",
            defaults={
                "description": description,
                "notes": saneyaml.dump(notes),
                "source_date_published": source_date_published,
                "platform": platform,
                "source_url": source_url,
            },
        )
    return 1
