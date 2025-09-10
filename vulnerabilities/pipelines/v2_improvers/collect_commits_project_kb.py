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

import saneyaml
from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import CodeFixV2
from vulnerabilities.pipelines import VulnerableCodePipeline


class CollectFixCommitsProjectKBPipeline(VulnerableCodePipeline):
    """
    Pipeline to collect fix commits from Project KB:
    https://github.com/SAP/project-kb/blob/main/MSR2019/dataset/vulas_db_msr2019_release.csv
    https://github.com/SAP/project-kb/blob/vulnerability-data/statements/*/*.yaml
    """

    pipeline_id = "kb_project_fix_commits"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/SAP/project-kb/blob/main/LICENSE.txt"
    importer_name = "Project KB Importer"
    qualified_name = "kb_project_fix_commits"
    repo_url_vulnerability_data = "git+https://github.com/SAP/project-kb@vulnerability-data"
    repo_url_main = "git+https://github.com/SAP/project-kb"

    @classmethod
    def steps(cls):
        return (cls.collect_fix_commits,)

    def collect_fix_commits(self):
        self.vcs_response_main = fetch_via_vcs(self.repo_url_main)
        self.vcs_response_vuln_data = fetch_via_vcs(self.repo_url_vulnerability_data)

        self.log(f"Processing ProjectKBP fix commits.")
        csv_database_filepath = (
            Path(self.vcs_response_main.dest_dir) / "MSR2019/dataset/vulas_db_msr2019_release.csv"
        )
        try:
            with open(csv_database_filepath, mode="r", newline="", encoding="utf-8") as f:
                reader = csv.reader(f)
                next(reader, None)  # Skip header row
                for row in reader:
                    if len(row) != 4:
                        continue
                    vulnerability_id, repo_url, commit_hash, label = row

                    if not vulnerability_id:
                        continue

                    try:
                        advisory = AdvisoryV2.objects.get(advisory_id=vulnerability_id)
                    except AdvisoryV2.DoesNotExist:
                        self.log(f"Can't find vulnerability_id: {vulnerability_id}")
                        continue

                    self.create_codefix_entries(advisory, repo_url, commit_hash, vulnerability_id)
        except FileNotFoundError:
            self.log(f"CSV file not found: {csv_database_filepath}")

        base_path = Path(self.vcs_response_vuln_data.dest_dir) / "statements"
        for file_path in base_path.rglob("*.yaml"):
            if file_path.name != "statement.yaml":
                continue

            with open(file_path) as f:
                vulnerability_fixes_data = saneyaml.load(f)

            vulnerability_id = vulnerability_fixes_data.get("vulnerability_id")
            if not vulnerability_id:
                continue

            try:
                advisory = AdvisoryV2.objects.get(advisory_id=vulnerability_id)
            except AdvisoryV2.DoesNotExist:
                self.log(f"Can't find vulnerability_id: {vulnerability_id}")
                continue

            for commit_data in vulnerability_fixes_data.get("fixes", []):
                for commit in commit_data.get("commits", []):
                    commit_id = commit.get("id")
                    repo_url = commit.get("repository")

                    if not commit_id or not repo_url:
                        continue

                    self.create_codefix_entries(advisory, repo_url, commit_id, vulnerability_id)

    def create_codefix_entries(self, advisory, repo_url, commit_id, vulnerability_id):
        repo_url = repo_url.rstrip("/").removesuffix(".git")
        vcs_url = f"{repo_url}/commit/{commit_id}"

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
        if self.vcs_response_main or self.vcs_response_vuln_data:
            self.log(f"Removing cloned repository")
            self.vcs_response_main.delete()
            self.vcs_response_vuln_data.delete()

    def on_failure(self):
        self.clean_downloads()
