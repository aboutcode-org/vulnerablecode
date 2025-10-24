#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import shutil
from datetime import timezone
from pathlib import Path

import dateparser
from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import GENERIC


class AospImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Pipeline to collect fix commits from Aosp Dataset:
    """

    pipeline_id = "aosp_dataset_fix_commits"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/quarkslab/aosp_dataset/blob/master/LICENSE"
    importer_name = "aosp_dataset"
    qualified_name = "aosp_dataset_fix_commits"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def clone(self):
        self.repo_url = "git+https://github.com/quarkslab/aosp_dataset"
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def advisories_count(self):
        root = Path(self.vcs_response.dest_dir)
        return sum(1 for _ in root.rglob("*.json"))

    def collect_advisories(self):
        self.log(f"Processing aosp_dataset fix commits.")
        base_path = Path(self.vcs_response.dest_dir) / "cves"
        for file_path in base_path.rglob("*.json"):
            if not file_path.name.startswith("CVE-"):
                continue

            with open(file_path) as f:
                vulnerability_data = json.load(f)

            vulnerability_id = vulnerability_data.get("cveId", [])
            if (
                not vulnerability_id or "," in vulnerability_id
            ):  # escape invalid multiple CVE-2017-13077, CVE-2017-13078
                continue

            summary = vulnerability_data.get("vulnerabilityType")
            date_reported = vulnerability_data.get("dateReported")
            date_published = dateparser.parse(date_reported) if date_reported else None
            if date_published and not date_published.tzinfo:
                date_published = date_published.replace(tzinfo=timezone.utc)

            severities = []
            severity_value = vulnerability_data.get("severity")
            if severity_value:
                severities.append(
                    VulnerabilitySeverity(
                        system=GENERIC,
                        value=severity_value,
                    )
                )

            references = []
            for commit_data in vulnerability_data.get("fixes", []):
                vcs_url = commit_data.get("patchUrl")

                if not vcs_url:
                    continue

                ref = ReferenceV2(
                    reference_type="commit",
                    url=vcs_url,
                )
                references.append(ref)

            yield AdvisoryData(
                advisory_id=vulnerability_id,
                summary=summary,
                references_v2=references,
                severities=severities,
                date_published=date_published,
                url=f"https://raw.githubusercontent.com/quarkslab/aosp_dataset/refs/heads/master/cves/{file_path.name}",
            )

    def clean_downloads(self):
        """Cleanup any temporary repository data."""
        self.log("Cleaning up local repository resources.")
        if hasattr(self, "repo") and self.repo.working_dir:
            shutil.rmtree(path=self.repo.working_dir)

    def on_failure(self):
        """Ensure cleanup is always performed on failure."""
        self.clean_downloads()
