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
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import DetectionRule
from vulnerabilities.models import DetectionRuleTypes
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.utils import find_all_cve
from vulnerabilities.utils import get_advisory_url


class SigmaRulesImproverPipeline(VulnerableCodePipeline):
    pipeline_id = "sigma_rules"

    repo_pattern = [
        ("https://github.com/SigmaHQ/sigma", "**/*.yml"),
        ("https://github.com/SamuraiMDR/sigma-rules", "**/*.yml"),
        ("https://github.com/mbabinski/Sigma-Rules", "**/*.yml"),
        ("https://github.com/P4T12ICK/Sigma-Rule-Repository", "**/*.yml"),
    ]

    license_urls = """
    https://github.com/SigmaHQ/Detection-Rule-License
    https://github.com/SamuraiMDR/sigma-rules/blob/main/LICENSE
    https://github.com/mbabinski/Sigma-Rules/blob/main/LICENSE
    https://github.com/P4T12ICK/Sigma-Rule-Repository/blob/master/LICENSE.md
    """

    @classmethod
    def steps(cls):
        return (
            cls.clone_repo,
            cls.collect_and_store_rules,
            cls.clean_downloads,
        )

    def clone_repo(self):
        self.cloned_repos = []
        for repo_url, rglob_pattern in self.repo_pattern:
            self.log(f"Cloning `{repo_url}`")
            vcs_response = fetch_via_vcs(f"git+{repo_url}")
            self.cloned_repos.append(
                {"repo_url": repo_url, "rglob_pattern": rglob_pattern, "vcs_response": vcs_response}
            )

    def collect_and_store_rules(self):
        """
        Collect Sigma YAML rules from the destination directory and store/update
        them as DetectionRule objects.
        """
        for cloned in self.cloned_repos:
            repo_url = cloned["repo_url"]
            rglob_pattern = cloned["rglob_pattern"]
            vcs_response = cloned["vcs_response"]
            base_directory = Path(vcs_response.dest_dir)
            yaml_files = [
                p
                for p in base_directory.rglob(rglob_pattern)
                if p.is_file()
                and not any(part in [".github", "images", "documentation"] for part in p.parts)
            ]

            rules_count = len(yaml_files)
            self.log(
                f"Enhancing the vulnerability with {rules_count:,d} rule records from {repo_url}"
            )
            progress = LoopProgress(total_iterations=rules_count, logger=self.log)
            for file_path in progress.iter(yaml_files):
                raw_text = file_path.read_text(encoding="utf-8")
                rule_documents = list(yaml.load_all(raw_text, yaml.FullLoader))

                rule_metadata = extract_sigma_metadata(rule_documents)
                source_url = get_advisory_url(
                    file=file_path,
                    base_path=base_directory,
                    url=f"{repo_url}/blob/master/",
                )

                cve_ids = find_all_cve(f"{file_path}\n{raw_text}")

                advisories = set()
                for cve_id in cve_ids:
                    alias = AdvisoryAlias.objects.filter(alias=cve_id).first()
                    if alias:
                        for adv in alias.advisories.all():
                            advisories.add(adv)
                    else:
                        advs = AdvisoryV2.objects.filter(advisory_id=cve_id)
                        for adv in advs:
                            advisories.add(adv)

                detection_rule, _ = DetectionRule.objects.update_or_create(
                    source_url=source_url,
                    rule_type=DetectionRuleTypes.SIGMA,
                    defaults={
                        "rule_metadata": rule_metadata,
                        "rule_text": raw_text,
                    },
                )

                for adv in advisories:
                    detection_rule.related_advisories.add(adv)

    def clean_downloads(self):
        for cloned in self.cloned_repos:
            vcs_response = cloned["vcs_response"]
            if vcs_response:
                self.log(f"Removing cloned repository: {vcs_response.dest_dir}")
                vcs_response.delete()

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
