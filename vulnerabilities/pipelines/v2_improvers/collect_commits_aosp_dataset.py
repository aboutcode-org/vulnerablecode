#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import json
from pathlib import Path

from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import CodeFixV2
from vulnerabilities.pipelines import VulnerableCodePipeline


class CollectFixCommitsAospDatasetPipeline(VulnerableCodePipeline):
    """
    Pipeline to collect fix commits from Aosp Dataset:
    """

    pipeline_id = "aosp_dataset_fix_commits"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/quarkslab/aosp_dataset/blob/master/LICENSE"
    importer_name = "aosp_dataset"
    qualified_name = "aosp_dataset_fix_commits"
    repo_url = "git+https://github.com/quarkslab/aosp_dataset"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_fix_commits,
        )

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def collect_fix_commits(self):
        self.log(f"Processing aosp_dataset fix commits.")
        base_path = Path(self.vcs_response.dest_dir) / "cves"
        for file_path in base_path.rglob("*.json"):
            if not file_path.name.startswith("CVE-"):
                continue

            with open(file_path) as f:
                vulnerability_data = json.load(f)

            vulnerability_id = vulnerability_data.get("cveId")
            if not vulnerability_id:
                continue

            try:
                advisories = AdvisoryV2.objects.filter(advisory_id__iendswith=vulnerability_id)
            except AdvisoryV2.DoesNotExist:
                self.log(f"Can't find vulnerability_id: {vulnerability_id}")
                continue

            for advisory in advisories:
                for commit_data in vulnerability_data.get("fixes", []):
                    vcs_url = commit_data.get("patchUrl")
                    for impact in advisory.impacted_packages.all():
                        for package in impact.affecting_packages.all():
                            code_fix, created = CodeFixV2.objects.get_or_create(
                                commits=[vcs_url],
                                advisory=advisory,
                                affected_package=package,
                            )

                            if created:
                                self.log(
                                    f"Created CodeFix entry for vulnerability_id: {vulnerability_id} with VCS URL {vcs_url}"
                                )

    def clean_downloads(self):
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()
