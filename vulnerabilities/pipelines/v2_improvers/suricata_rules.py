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

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import DetectionRule
from vulnerabilities.models import DetectionRuleTypes
from vulnerabilities.pipes.rules import BaseRuleImproverPipeline
from vulnerabilities.utils import find_all_cve_rule
from vulnerabilities.utils import get_advisory_url


class SuricataRulesImproverPipeline(BaseRuleImproverPipeline):
    rglob_patterns = ["**/*.rules"]

    def collect_and_store_rules(self):
        """
        Collect Suricata rules using rglob patterns and store/update them as DetectionRule objects.
        """
        base_directory = Path(self.vcs_response.dest_dir)
        suricata_files = set()
        for pattern in self.rglob_patterns:
            for p in base_directory.glob(pattern):
                if p.is_file():
                    suricata_files.add(p)

        rules_count = len(suricata_files)
        self.log(f"Enhancing vulnerability data with {rules_count:,d} records from {self.repo_url}")
        progress = LoopProgress(total_iterations=rules_count, logger=self.log)
        for file_path in progress.iter(suricata_files):
            raw_text = file_path.read_text(encoding="utf-8")
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
                rule_type=DetectionRuleTypes.SURICATA,
                defaults={
                    "rule_text": raw_text,
                },
            )

            for adv in advisories:
                detection_rule.related_advisories.add(adv)


class SudohyakSuricataImproverPipeline(SuricataRulesImproverPipeline):
    pipeline_id = "sudohyak_suricata"
    repo_url = "https://github.com/sudohyak/suricata-rules"
    license_url = "https://github.com/sudohyak/suricata-rules/blob/main/LICENSE"


class OISFSuricataImproverPipeline(SuricataRulesImproverPipeline):
    pipeline_id = "oisf_suricata"
    repo_url = "https://github.com/OISF/suricata"
    rglob_patterns = ["rules/**/*.rules"]
    license_url = "https://github.com/OISF/suricata?tab=GPL-2.0-2-ov-file"
