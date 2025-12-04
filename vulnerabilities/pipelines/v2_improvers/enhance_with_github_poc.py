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

from aboutcode.pipeline import LoopProgress
from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryPOC
from vulnerabilities.pipelines import VulnerableCodePipeline


class GithubPocsImproverPipeline(VulnerableCodePipeline):
    """
    Pipeline to Collect an exploit-PoCs repository, parse exploit JSON files,
    match them to advisories via aliases, and update/create POC records.
    """

    pipeline_id = "enhance_with_github_poc"
    repo_url = "git+https://github.com/nomi-sec/PoC-in-GitHub"

    @classmethod
    def steps(cls):
        return (
            cls.clone_repo,
            cls.collect_and_store_exploits,
            cls.clean_downloads,
        )

    def clone_repo(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def collect_and_store_exploits(self):
        """
        Parse PoC JSON files, match them to advisories via aliases,
        and create or update related exploit records.
        """

        base_directory = Path(self.vcs_response.dest_dir)
        json_files = list(base_directory.rglob("**/*.json"))
        exploits_count = len(json_files)
        self.log(f"Enhancing the vulnerability with {exploits_count:,d} exploit records")
        progress = LoopProgress(total_iterations=exploits_count, logger=self.log)
        for file_path in progress.iter(json_files):
            with open(file_path, "r") as f:
                try:
                    exploits_data = json.load(f)
                except json.JSONDecodeError:
                    self.log(f"Invalid JSON in {file_path}, skipping.")
                    continue

            filename = file_path.stem.strip()

            advisories = set()
            try:
                if alias := AdvisoryAlias.objects.get(alias=filename):
                    for adv in alias.advisories.all():
                        advisories.add(adv)
            except AdvisoryAlias.DoesNotExist:
                self.log(f"Advisory {filename} not found.")
                continue

            for advisory in advisories:
                for exploit_data in exploits_data:
                    exploit_repo_url = exploit_data.get("html_url")
                    if not exploit_repo_url:
                        continue

                    AdvisoryPOC.objects.update_or_create(
                        advisory=advisory,
                        url=exploit_repo_url,
                        defaults={
                            "created_at": exploit_data.get("created_at"),
                            "updated_at": exploit_data.get("updated_at"),
                        },
                    )

        self.log(f"Successfully added {exploits_count:,d} poc exploit advisory")

    def clean_downloads(self):
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()
