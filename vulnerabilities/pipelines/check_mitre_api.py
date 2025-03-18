#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import re
import time
from datetime import datetime
from datetime import timedelta

import requests
from aboutcode.pipeline import LoopProgress

from vulnerabilities.improvers.vulnerability_status import MITRE_API_URL
from vulnerabilities.models import Alias
from vulnerabilities.models import VulnerabilityChangeLog
from vulnerabilities.models import VulnerabilityStatusType
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.utils import fetch_response
from vulnerabilities.utils import get_item


class DetectNonExistentCvesPipeline(VulnerableCodePipeline):
    """
    Pipeline to detect and properly mark reserved or non-existent CVEs.
    """

    pipeline_id = "detect_nonexistent_cves"

    @classmethod
    def steps(cls):
        return (cls.process_cves,)

    def process_cves(self):
        """
        Process all CVE IDs in the database to detect reserved or non-existent CVEs.
        """
        # Get all CVE aliases
        cve_aliases = Alias.objects.filter(alias__regex=r"^CVE-\d{4}-\d{4,}$").select_related(
            "vulnerability"
        )

        self.log(f"Processing {cve_aliases.count():,d} CVE IDs for reserved/non-existent status")

        progress = LoopProgress(
            total_iterations=cve_aliases.count(),
            logger=self.log,
            progress_step=5,
        )

        reserved_count = 0
        invalid_count = 0
        error_count = 0
        rate_limited = False

        batch_size = 100
        for cve_alias in progress.iter(
            cve_aliases.order_by("alias").paginated(per_page=batch_size)
        ):
            if rate_limited:
                # Add a delay if we hit rate limits
                time.sleep(1)

            cve_id = cve_alias.alias
            vulnerability = cve_alias.vulnerability

            # Skip if vulnerability doesn't exist
            if not vulnerability:
                continue

            # Skip if vulnerability already has a non-PUBLISHED status
            if vulnerability.status != VulnerabilityStatusType.PUBLISHED:
                continue

            try:
                status = self.check_cve_status(cve_id)

                if status == VulnerabilityStatusType.RESERVED:
                    self.update_vulnerability_status(vulnerability, status)
                    reserved_count += 1
                elif status == VulnerabilityStatusType.INVALID:
                    self.update_vulnerability_status(vulnerability, status)
                    invalid_count += 1

            except requests.exceptions.HTTPError as http_error:
                if http_error.response.status_code == 429:  # Rate limited
                    rate_limited = True
                    self.log(f"Rate limited by MITRE API. Adding delay.")
                    continue
                else:
                    self.log(f"HTTP error for {cve_id}: {http_error}")
                    error_count += 1
            except Exception as e:
                self.log(f"Error processing {cve_id}: {e}")
                error_count += 1

        self.log(
            f"Completed. Found {reserved_count} reserved CVEs, {invalid_count} invalid CVEs. Encountered {error_count} errors."
        )

    def check_cve_status(self, cve_id):
        """
        Check the status of a CVE ID using the MITRE API.
        Returns the appropriate VulnerabilityStatusType.
        """
        url = f"{MITRE_API_URL}{cve_id}"

        try:
            response = fetch_response(url=url)
            response_json = response.json()

            cve_state = get_item(response_json, "cveMetadata", "state") or None

            try:
                tags = get_item(response_json, "containers", "cna", "tags") or []
            except (TypeError, AttributeError, KeyError) as e:
                tags = []
                self.log(f"Missing attribute tags in {response_json}")

            if "disputed" in tags:
                return VulnerabilityStatusType.DISPUTED

            if cve_state:
                if cve_state == "REJECTED":
                    return VulnerabilityStatusType.INVALID
                elif cve_state == "RESERVED":
                    return VulnerabilityStatusType.RESERVED
                else:
                    return VulnerabilityStatusType.PUBLISHED

            return VulnerabilityStatusType.PUBLISHED

        except requests.exceptions.HTTPError as http_error:
            if http_error.response.status_code == 404:
                # CVE not found in MITRE database
                return VulnerabilityStatusType.INVALID
            raise

    def update_vulnerability_status(self, vulnerability, status):
        """
        Update the status of a vulnerability and create a change log entry.
        """

        old_status = vulnerability.status
        vulnerability.status = status
        vulnerability.save()

        # Create change log entry
        VulnerabilityChangeLog.objects.create(
            vulnerability=vulnerability,
            field="status",
            old_value=old_status,
            new_value=status,
            automated=True,
            message=f"Updated CVE status via MITRE API check",
            data_source=self.pipeline_id,
        )
