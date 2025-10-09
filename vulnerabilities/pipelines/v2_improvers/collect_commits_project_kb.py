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

from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import CodeFixV2
from vulnerabilities.pipelines import VulnerableCodePipeline


class CollectFixCommitsProjectKBPipeline(VulnerableCodePipeline):
    """
    Pipeline to collect fix commits from Project KB:
    https://github.com/SAP/project-kb/blob/main/MSR2019/dataset/vulas_db_msr2019_release.csv
    """

    pipeline_id = "kb_project_fix_commits"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/SAP/project-kb/blob/main/LICENSE.txt"
    qualified_name = "kb_project_fix_commits"
    repo_url = "git+https://github.com/SAP/project-kb"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_fix_commits,
        )

    def clone(self):
        self.log("Cloning repositories for ProjectKB fix commits from CSV...")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def collect_fix_commits(self):
        self.log("Collecting fix commits from ProjectKB...")

        csv_path = Path(self.vcs_response.dest_dir) / "MSR2019/dataset/vulas_db_msr2019_release.csv"

        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)  # skip header
            rows = [r for r in reader if len(r) == 4 and r[0]]

        vuln_ids = {r[0] for r in rows}
        advisories = AdvisoryV2.objects.filter(advisory_id__in=vuln_ids).prefetch_related(
            "impacted_packages__affecting_packages"
        )
        advisory_map = {a.advisory_id: a for a in advisories}

        codefixes = []
        for vuln_id, repo_url, commit, _ in rows:
            advisory = advisory_map.get(vuln_id)
            if not advisory:
                continue

            repo_url = repo_url.rstrip("/").removesuffix(".git")
            vcs_url = f"{repo_url}/commit/{commit}"

            for impact in advisory.impacted_packages.all():
                for pkg in impact.affecting_packages.all():
                    codefixes.append(
                        CodeFixV2(
                            commits=[vcs_url],
                            advisory=advisory,
                            affected_package=pkg,
                        )
                    )

        if codefixes:
            CodeFixV2.objects.bulk_create(codefixes, ignore_conflicts=True)
            self.log(f"Created {len(codefixes)} CodeFix entries.")
        else:
            self.log("No CodeFix entries created.")

    def clean_downloads(self):
        """Remove the cloned repository from disk."""
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()
