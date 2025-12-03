#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import datetime
from pathlib import Path

import yaml
from aboutcode.pipeline import LoopProgress
from fetchcode.vcs import fetch_via_vcs

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
        them as DetectionRule objects.
        """

        base_directory = Path(self.vcs_response.dest_dir)
        yaml_files = [
            p
            for p in base_directory.rglob("**/*.yml")
            if not any(part in [".github", "images", "documentation"] for part in p.parts)
        ]

        rules_count = len(yaml_files)
        self.log(f"Enhancing the vulnerability with {rules_count:,d} rule records")
        progress = LoopProgress(total_iterations=rules_count, logger=self.log)
        for file_path in progress.iter(yaml_files):
            raw_text = file_path.read_text(encoding="utf-8")
            rule_documents = list(yaml.load_all(raw_text, yaml.FullLoader))

            rule_metadata = extract_sigma_metadata(rule_documents)
            rule_url = f"https://raw.githubusercontent.com/SigmaHQ/sigma/refs/heads/master/{file_path.relative_to(base_directory)}"
            cve_ids = find_all_cve(str(file_path))

            found_advisories = set()
            for cve_id in cve_ids:
                try:
                    alias = AdvisoryAlias.objects.get(alias=cve_id)
                    for adv in alias.advisories.all():
                        found_advisories.add(adv)
                except AdvisoryAlias.DoesNotExist:
                    self.log(f"AdvisoryAlias {cve_id}: {file_path.name} not found.")
                    continue

            for adv in found_advisories:
                DetectionRule.objects.update_or_create(
                    rule_text=raw_text,
                    rule_type=DetectionRuleTypes.SIGMA,
                    advisory=adv,
                    defaults={
                        "rule_metadata": rule_metadata,
                        "source_url": rule_url,
                    },
                )

            if not found_advisories:
                DetectionRule.objects.update_or_create(
                    rule_text=raw_text,
                    rule_type=DetectionRuleTypes.SIGMA,
                    advisory=None,
                    defaults={
                        "rule_metadata": rule_metadata,
                        "source_url": rule_url,
                    },
                )

    def clean_downloads(self):
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()


def extract_sigma_metadata(rule_documents):
    """
    Extract Sigma metadata from Sigma YAML rules
    """
    if not rule_documents:
        return None

    first_document = rule_documents[0]
    metadata = {
        "status": first_document.get("status"),
        "author": first_document.get("author"),
        "date": first_document.get("date"),
        "title": first_document.get("title"),
        "id": first_document.get("id"),
    }

    rule_date = metadata.get("date")

    if isinstance(rule_date, (datetime.date, datetime.datetime)):
        metadata["date"] = rule_date.isoformat()

    return metadata
