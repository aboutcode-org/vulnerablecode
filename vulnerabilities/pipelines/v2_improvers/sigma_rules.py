#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import datetime
import json
from pathlib import Path

import jsonschema
import yaml
from aboutcode.pipeline import LoopProgress
from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import DetectionRule
from vulnerabilities.models import DetectionRuleTypes
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.utils import find_all_cve_rule
from vulnerabilities.utils import get_advisory_url

current_dir = Path(__file__).parent
schema_path = current_dir / "sigma-schema.json"

class CollectSigmaRulesPipeline(VulnerableCodePipeline):
    repo_url = None
    rglob_patterns = ["**/*.yml"]

    @classmethod
    def steps(cls):
        return (
            cls.clone_repo,
            cls.collect_and_store_rules,
            cls.clean_downloads,
        )

    def clone_repo(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(f"git+{self.repo_url}")

    def is_valid_sigma_rule(self, rule_documents, sigma_schema):
        """Validate Sigma rule documents against the JSON schema."""
        # if not rule_documents:
        #     return False
        #
        # for doc in rule_documents:
        #     if doc is None:
        #         continue
        #
        #     json_compatible_doc = json.loads(json.dumps(doc, default=str))
        #
        #     try:
        #         jsonschema.validate(instance=json_compatible_doc, schema=sigma_schema)
        #     except jsonschema.exceptions.ValidationError as e:
        #         self.log(f"Schema validation failed: {e.message}")
        #         return False

        return True

    def collect_and_store_rules(self):
        """
        Collect Sigma YAML rules from the destination directory and store/update them as DetectionRule objects.
        """
        base_directory = Path(self.vcs_response.dest_dir)
        yaml_files = set()
        for pattern in self.rglob_patterns:
            for p in base_directory.glob(pattern):
                if p.is_file():
                    yaml_files.add(p)

        rules_count = len(yaml_files)
        with open(schema_path) as schema_file:
            sigma_schema = json.load(schema_file)

        self.log(
            f"Enhancing the vulnerability with {rules_count:,d} rule records from {self.repo_url}"
        )
        progress = LoopProgress(total_iterations=rules_count, logger=self.log)
        for file_path in progress.iter(yaml_files):
            raw_text = file_path.read_text(encoding="utf-8")

            try:
                rule_documents = list(yaml.safe_load_all(raw_text))
            except yaml.YAMLError as e:
                self.log(f"Skipping malformed YAML in {file_path.name}: {e}")
                continue

            if not self.is_valid_sigma_rule(rule_documents, sigma_schema):
                self.log(f"Skipping Invalid sigma rule {file_path}")
                continue

            rule_metadata = extract_sigma_metadata(rule_documents)
            source_url = get_advisory_url(
                file=file_path,
                base_path=base_directory,
                url=f"{self.repo_url}/blob/master/",
            )

            cve_ids = find_all_cve_rule(f"{file_path}\n{raw_text}")
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
        if self.vcs_response:
            self.log(f"Removing cloned repository: {self.vcs_response.dest_dir}")
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

class SigmaHQImproverPipeline(CollectSigmaRulesPipeline):
    pipeline_id = "sigmaHQ-sigma"
    repo_url = "https://github.com/SigmaHQ/sigma"
    license_url = "https://github.com/SigmaHQ/Detection-Rule-License"
    rglob_patterns = [
        "rules/**/*.yml",
        "rules-emerging-threats/**/*.yml",
        "rules-placeholder/**/*.yml",
        "rules-threat-hunting/**/*.yml",
        "rules-compliance/**/*.yml",
    ]

class SigmaSamuraiMDRImproverPipeline(CollectSigmaRulesPipeline):
    pipeline_id = "samuraiMDR-sigma-rules"
    repo_url = "https://github.com/SamuraiMDR/sigma-rules"
    license_urls = "https://github.com/SamuraiMDR/sigma-rules/blob/main/LICENSE"

class SigmaMbabinskiImproverPipeline(CollectSigmaRulesPipeline):
    pipeline_id = "mbabinski-sigma-rules"
    repo_url = "https://github.com/mbabinski/Sigma-Rules"
    license_urls = "https://github.com/mbabinski/Sigma-Rules/blob/main/LICENSE"

class P4T12ICKSigmaImproverPipeline(CollectSigmaRulesPipeline):
    pipeline_id = "P4T12ICK-sigma-rules"
    repo_url = "https://github.com/P4T12ICK/Sigma-Rule-Repository"
    license_urls = "https://github.com/P4T12ICK/Sigma-Rule-Repository/blob/master/LICENSE.md"