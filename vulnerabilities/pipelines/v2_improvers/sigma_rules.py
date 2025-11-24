#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path

import saneyaml
from aboutcode.pipeline import LoopProgress
from fetchcode.vcs import fetch_via_vcs
from yaml import YAMLError

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryDetectionRule
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.utils import find_all_cve


class SigmaRulesImproverPipeline(VulnerableCodePipeline):
    pipeline_id = "sigma_rules"
    repo_url = "git+https://github.com/SigmaHQ/sigma"
    license_url = "https://github.com/SigmaHQ/Detection-Rule-License"

    @classmethod
    def steps(cls):
        return (
            cls.clone_repo,
            cls.collect_and_store_rules,
            cls.clean_downloads,
        )

    def clone_repo(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def collect_and_store_rules(self):
        """
        Collect Sigma YAML rules from the destination directory and store/update
        them as AdvisoryDetectionRule objects.
        """

        base_directory = Path(self.vcs_response.dest_dir)
        yaml_files = list(base_directory.rglob("**/*.yml"))
        rules_count = len(yaml_files)

        self.log(f"Enhancing the vulnerability with {rules_count:,d} rule records")
        progress = LoopProgress(total_iterations=rules_count, logger=self.log)
        for file_path in progress.iter(yaml_files):
            cve_ids = find_all_cve(str(file_path))
            if not cve_ids or len(cve_ids) > 1:
                continue

            cve_id = cve_ids[0]

            with open(file_path, "r") as f:
                try:
                    rule_data = saneyaml.load(f)
                except YAMLError as err:
                    self.log(f"Invalid YAML in {file_path}: {err}. Skipping.")
                    continue

            advisories = set()
            try:
                if alias := AdvisoryAlias.objects.get(alias=cve_id):
                    for adv in alias.advisories.all():
                        advisories.add(adv)
            except AdvisoryAlias.DoesNotExist:
                self.log(f"Advisory {file_path.name} not found.")
                continue

            rule_text = saneyaml.dump(rule_data)
            rule_url = f"https://raw.githubusercontent.com/SigmaHQ/sigma/refs/heads/master/{file_path.relative_to(base_directory)}"

            for advisory in advisories:
                AdvisoryDetectionRule.objects.update_or_create(
                    advisory=advisory,
                    rule_type="sigma",
                    defaults={
                        "rule_text": rule_text,
                        "source_url": rule_url,
                    },
                )

        self.log(f"Successfully added {rules_count:,d} rules advisory")

    def clean_downloads(self):
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()
