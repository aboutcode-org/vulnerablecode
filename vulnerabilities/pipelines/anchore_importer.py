#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from datetime import datetime
from typing import Iterable

import requests
import yaml
from packageurl import PackageURL
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline


class AnchoreImporterPipeline(VulnerableCodeBaseImporterPipeline):
    """Collect advisories from Anchore's NVD overrides."""

    pipeline_id = "anchore_importer"
    root_url = "https://github.com/anchore/nvd-data-overrides"
    license_url = "https://github.com/anchore/nvd-data-overrides/blob/main/LICENSE"
    spdx_license_expression = "CC0-1.0"  # License of Anchore's data
    importer_name = "Anchore NVD Overrides Importer"

    @classmethod
    def steps(cls):
        return (
            cls.collect_and_store_advisories,
            cls.import_new_advisories,
        )

    def advisories_count(self) -> int:
        raw_data = self.fetch_data()
        return len(raw_data)

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        raw_data = self.fetch_data()
        for entry in raw_data:
            yield self.parse_advisory_data(entry)

    def fetch_data(self):
        """Fetch Anchore's NVD overrides from their GitHub repository."""
        url = "https://raw.githubusercontent.com/anchore/nvd-data-overrides/main/overrides.yaml"
        response = requests.get(url)
        response.raise_for_status()
        return yaml.safe_load(response.text)  # Correct YAML parsing

    def parse_advisory_data(self, raw_data) -> AdvisoryData:
        """Parse a single advisory entry into an AdvisoryData object."""
        # Ensure required fields are present
        if not all(key in raw_data for key in ["cve_id", "package_name", "affected_versions"]):
            return None

        purl = PackageURL(type="generic", name=raw_data["package_name"])
        affected_version_range = raw_data["affected_versions"]  # Use raw version range string
        fixed_version = (
            SemverVersion(raw_data["fixed_version"]) if raw_data.get("fixed_version") else None
        )

        affected_package = AffectedPackage(
            package=purl,
            affected_version_range=affected_version_range,
            fixed_version=fixed_version,
        )

        references = [
            Reference(url=url) for url in raw_data.get("references", []) if url
        ]
        date_published = (
            datetime.strptime(raw_data["published_date"], "%Y-%m-%d")
            if raw_data.get("published_date")
            else None
        )

        return AdvisoryData(
            aliases=[raw_data["cve_id"]],
            summary=raw_data.get("description", ""),
            affected_packages=[affected_package],
            references=references,
            date_published=date_published,
        )