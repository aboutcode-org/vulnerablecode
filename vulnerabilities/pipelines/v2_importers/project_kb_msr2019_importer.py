#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import csv
from pathlib import Path
from typing import Iterable

from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipes.advisory import append_patch_classifications


class ProjectKBMSR2019Pipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    ProjectKB Importer Pipeline
    Collect advisory from ProjectKB data:
    - CSV database https://github.com/SAP/project-kb/blob/main/MSR2019/dataset/vulas_db_msr2019_release.csv
    """

    pipeline_id = "project-kb-msr-2019_v2"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/SAP/project-kb/blob/main/LICENSE.txt"
    repo_url = "git+https://github.com/SAP/project-kb"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def clone(self):
        self.log("Cloning ProjectKB advisory data...")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def advisories_count(self):
        csv_path = Path(self.vcs_response.dest_dir) / "MSR2019/dataset/vulas_db_msr2019_release.csv"

        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)
            count = sum(1 for _ in reader)

        self.log(f"Estimated advisories to process: {count}")
        return count

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        self.log("Collecting fix commits from ProjectKB ( vulas_db_msr2019_release )...")
        csv_path = Path(self.vcs_response.dest_dir) / "MSR2019/dataset/vulas_db_msr2019_release.csv"

        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)  # skip header

            for row in reader:
                if len(row) != 4:
                    continue

                vuln_id, vcs_url, commit_hash, poc = row

                if not vuln_id or not vcs_url or not commit_hash:
                    continue

                patches = []
                affected_packages = []
                references = []
                append_patch_classifications(
                    url=vcs_url,
                    commit_hash=commit_hash,
                    patch_text=None,
                    affected_packages=affected_packages,
                    references=references,
                    patches=patches,
                )

                yield AdvisoryDataV2(
                    advisory_id=vuln_id,
                    affected_packages=affected_packages,
                    patches=patches,
                    references=references,
                    url="https://github.com/SAP/project-kb/blob/main/MSR2019/dataset/vulas_db_msr2019_release.csv",
                )

    def clean_downloads(self):
        """Remove the cloned repository from disk."""
        self.log("Removing cloned repository...")
        if self.vcs_response:
            self.vcs_response.delete()

    def on_failure(self):
        """Ensure cleanup happens on pipeline failure."""
        self.clean_downloads()
