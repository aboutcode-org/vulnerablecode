#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os
from datetime import date
from itertools import chain

from django.core.management.base import BaseCommand

from vulnerabilities import models
from vulnerabilities.importers.nvd import BASE_URL as nvd_base_url
from vulnerabilities.importers.nvd import NVDImporter as nvd_utils


class Command(BaseCommand):
    """
    This script creates a mapping of CPEs to PURLs grouped by the affecting CVE.
    It does this by doing the following:
      1. Iterate over all CVEs found in VulnerableCode's db.
      2. Look for the CVE being iterated upon in the NVD.
      3. Get the list of all CPEs which are affected by this CVE from NVD entry.
      4. Get the list of all PURLs which are affected by this CVE from VulnerableCode's db.
      5. Map the list of CPEs and PURLs from #3 and #4 together.
    """

    def add_arguments(self, parser):

        parser.add_argument(
            "--vulnerable_purls_only", action="store_true", help="Map only vulnerable PURLs to CPEs"
        )

        parser.add_argument(
            "--patched_purls_only", action="store_true", help="Map only patching PURLs to CPEs"
        )

    @staticmethod
    def get_packages(vulnerability, vulnerable_purls_only, patched_purls_only):
        if vulnerable_purls_only and not patched_purls_only:
            return vulnerability.vulnerable_packages.all()

        elif patched_purls_only and not vulnerable_purls_only:
            return vulnerability.patched_packages.all()

        return chain(vulnerability.patched_packages.all(), vulnerability.vulnerable_packages.all())

    def handle(self, *args, **options):
        current_year = date.today().year
        # NVD json feeds start from 2002.
        for year in range(2002, current_year + 1):
            self.stdout.write(f"Processing CPEs from year {year}")
            download_url = nvd_base_url.format(year)
            nvd_data = nvd_utils.fetch(download_url)

            vulnerabilities = list(
                models.Vulnerability.objects.filter(vulnerability_id__startswith=f"CVE-{year}")
                .prefetch_related("vulnerable_packages")
                .prefetch_related("patched_packages")
            )

            vulnerabilities = {
                vulnerability.vulnerability_id: vulnerability for vulnerability in vulnerabilities
            }
            purl_cpe_mapping = []

            for cve_item in nvd_data["CVE_Items"]:
                cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]
                if cve_id not in vulnerabilities:
                    continue

                purl_cpe_mapping.append({})
                purl_cpe_mapping[-1]["cve_id"] = cve_id
                purl_cpe_mapping[-1]["purls"] = []
                purl_cpe_mapping[-1]["cpes"] = list(nvd_utils.extract_cpes(cve_item))

                packages = self.get_packages(
                    vulnerabilities[cve_id],
                    options["vulnerable_purls_only"],
                    options["patched_purls_only"],
                )
                for package in packages:
                    purl_cpe_mapping[-1]["purls"].append(package.package_url)

            if not os.path.exists("cpe2purl"):
                os.mkdir("cpe2purl")

            with open(os.path.join("cpe2purl", f"{year}.json"), "w") as f:
                json.dump(purl_cpe_mapping, f, indent=4)

        path = os.path.abspath("cpe2purl")
        self.stdout.write(self.style.SUCCESS(f"Successfully created the mappings. Check {path}"))
