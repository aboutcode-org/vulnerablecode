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

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import DetectionRule
from vulnerabilities.models import DetectionRuleTypes
from vulnerabilities.pipelines import VulnerableCodePipeline


class DetectionRulesPipeline(VulnerableCodePipeline):
    """
    Pipeline to collect vulnerability scanner rules (Sigma, YARA, Suricata, ClamAV entries)
    """

    pipeline_id = "detection_rules"
    license_url = "https://github.com/ziadhany/detection-rules-collector/blob/master/LICENSE"
    precedence = 200

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_detection_rules,
            cls.clean_downloads,
        )

    def clone(self):
        self.repo_url = "git+https://github.com/aboutcode-data/detection-rules-collector"
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def advisories_count(self):
        root = Path(self.vcs_response.dest_dir)
        return sum(1 for _ in root.rglob("*.json"))

    def collect_detection_rules(self):
        base_path = Path(self.vcs_response.dest_dir) / "data"
        rule_type_mapping = {
            DetectionRuleTypes.YARA: "yara/**/*.json",
            DetectionRuleTypes.SURICATA: "suricata/**/*.json",
            DetectionRuleTypes.SIGMA: "sigma/**/*.json",
            DetectionRuleTypes.CLAMAV: "clamav/**/*.json",
        }

        for rule_type, glob_pattern in rule_type_mapping.items():
            for file_path in base_path.glob(glob_pattern):
                with open(file_path, "r") as f:
                    try:
                        json_data = json.load(f)
                    except json.JSONDecodeError:
                        self.log(f"Failed to parse JSON in {file_path}")
                        continue

                source_url = json_data.get("source_url")
                for rule in json_data.get("rules", []):
                    advisories = set()
                    for vulnerability_id in rule.get("vulnerabilities", []):
                        try:
                            if alias := AdvisoryAlias.objects.get(alias=vulnerability_id):
                                for adv in alias.advisories.all():
                                    advisories.add(adv)
                            else:
                                advs = AdvisoryV2.objects.filter(
                                    advisory_id=vulnerability_id
                                ).latest_per_avid()
                                for adv in advs:
                                    advisories.add(adv)
                        except AdvisoryAlias.DoesNotExist:
                            self.log(f"No advisory found for aliases {vulnerability_id}")

                    raw_text = rule.get("rule_text")
                    detection_rule, _ = DetectionRule.objects.get_or_create(
                        rule_text=raw_text,
                        rule_type=rule_type,
                        defaults={
                            "source_url": source_url,
                        },
                    )
                    if advisories:
                        detection_rule.related_advisories.add(*advisories)

    def clean_downloads(self):
        """Cleanup any temporary repository data."""
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        """Ensure cleanup is always performed on failure."""
        self.clean_downloads()
