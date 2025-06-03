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

from vulnerabilities.models import Alias
from vulnerabilities.models import Exploit
from vulnerabilities.pipelines import VulnerableCodePipeline


class VulnerabilityKevPipeline(VulnerableCodePipeline):
    """
    Retrieve KEV data, iterate through it to identify vulnerabilities
    by their associated aliases, and create or update the corresponding Exploit instances.
    """

    pipeline_id = "enhance_with_kev"
    license_expression = None

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

        vulnerability_exploit_count = 0
        progress = LoopProgress(total_iterations=fetched_exploit_count, logger=self.log)

        for record in progress.iter(self.kev_data.get("vulnerabilities", [])):
            vulnerability_exploit_count += add_vulnerability_exploit(
                kev_vul=record,
                logger=self.log,
            )

        self.log(f"Successfully added {vulnerability_exploit_count:,d} kev exploit")


def add_vulnerability_exploit(kev_vul, logger):
    cve_id = kev_vul.get("cveID")

    if not cve_id:
        return 0

    vulnerability = None
    try:
        if alias := Alias.objects.get(alias=cve_id):
            vulnerability = alias.vulnerability
    except Alias.DoesNotExist:
        logger(f"No vulnerability found for aliases {cve_id}")
        return 0

    Exploit.objects.update_or_create(
        vulnerability=vulnerability,
        data_source="KEV",
        defaults={
            "description": kev_vul["shortDescription"],
            "date_added": kev_vul["dateAdded"],
            "required_action": kev_vul["requiredAction"],
            "due_date": kev_vul["dueDate"],
            "notes": kev_vul["notes"],
            "known_ransomware_campaign_use": True
            if kev_vul["knownRansomwareCampaignUse"] == "Known"
            else False,
        },
    )
    return 1
