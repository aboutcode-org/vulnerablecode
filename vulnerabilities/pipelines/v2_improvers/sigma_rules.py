#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path

from aboutcode.pipeline import LoopProgress
from fetchcode.vcs import fetch_via_vcs
from yaml import YAMLError

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import DetectionRule
from vulnerabilities.models import DetectionRuleTypes
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
            if any(part in [".github", "images", "documentation"] for part in file_path.parts):
                continue

            with open(file_path, "r") as f:
                try:
                    rule_data = f.read()
                except YAMLError as err:
                    self.log(f"Invalid YAML in {file_path}: {err}. Skipping.")
                    continue

            rule_url = f"https://raw.githubusercontent.com/SigmaHQ/sigma/refs/heads/master/{file_path.relative_to(base_directory)}"
            cve_ids = find_all_cve(str(file_path))
            found_advisories = set()
            for cve_id in cve_ids:
                try:
                    alias = AdvisoryAlias.objects.get(alias=cve_id)
                    for adv in alias.advisories.all():
                        found_advisories.add(adv)
                except AdvisoryAlias.DoesNotExist:
                    self.log(f"Advisory {file_path.name} not found.")
                    continue

            for adv in found_advisories:
                DetectionRule.objects.update_or_create(
                    rule_text=rule_data,
                    advisory=adv,
                    defaults={
                        "rule_type": DetectionRuleTypes.SIGMA,
                        "source_url": rule_url,
                    },
                )

            if not found_advisories:
                DetectionRule.objects.update_or_create(
                    rule_text=rule_data,
                    advisory=None,
                    defaults={
                        "rule_type": DetectionRuleTypes.SIGMA,
                        "source_url": rule_url,
                    },
                )
            self.log(f"Successfully processed rules.")

    def clean_downloads(self):
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()
