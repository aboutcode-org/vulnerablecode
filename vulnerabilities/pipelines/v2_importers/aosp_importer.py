#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
from datetime import timezone
from pathlib import Path
from urllib.parse import quote

import dateparser
from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipes.advisory import append_patch_classifications
from vulnerabilities.severity_systems import GENERIC


class AospImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Pipeline to collect fix commits from Aosp Dataset:
    """

    pipeline_id = "aosp_dataset_fix_commits"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/quarkslab/aosp_dataset/blob/master/LICENSE"

    precedence = 200

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

            vulnerability_ids = vulnerability_data.get("cveId", "")
            for vulnerability_id in vulnerability_ids.split(","):
                if not vulnerability_id:
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

                patches = []
                affected_packages = []
                references = []
                for commit_data in vulnerability_data.get("fixes", []):
                    patch_url = commit_data.get("patchUrl")
                    commit_id = commit_data.get("commitId")

                    append_patch_classifications(
                        url=patch_url,
                        commit_hash=commit_id,
                        patch_text=None,
                        affected_packages=affected_packages,
                        references=references,
                        patches=patches,
                    )

                url = (
                    "https://raw.githubusercontent.com/quarkslab/aosp_dataset/refs/heads/master/cves/"
                    f"{quote(file_path.name)}"
                )

                yield AdvisoryDataV2(
                    advisory_id=vulnerability_id,
                    summary=summary,
                    affected_packages=affected_packages,
                    severities=severities,
                    patches=patches,
                    references=references,
                    date_published=date_published,
                    url=url,
                )

    def clean_downloads(self):
        """Cleanup any temporary repository data."""
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        """Ensure cleanup is always performed on failure."""
        self.clean_downloads()
