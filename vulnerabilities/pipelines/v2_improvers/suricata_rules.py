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

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import DetectionRule
from vulnerabilities.models import DetectionRuleTypes
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.utils import find_all_cve
from vulnerabilities.utils import get_advisory_url


class SuricataRulesImproverPipeline(VulnerableCodePipeline):
    pipeline_id = "suricata-rules"

    repo_pattern = [
        ("https://github.com/sudohyak/suricata-rules", "**/*.rules"),
        ("https://github.com/OISF/suricata", "rules/**/*.rules"),
    ]

    license_urls = """
    https://github.com/sudohyak/suricata-rules/blob/main/LICENSE

    https://github.com/OISF/suricata?tab=GPL-2.0-2-ov-file
    https://github.com/OISF/suricata?tab=GPL-2.0-1-ov-file
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
        Collect Suricata rules using rglob patterns and store/update
        them as DetectionRule objects.
        """
        for cloned in self.cloned_repos:
            repo_url = cloned["repo_url"]
            rglob_pattern = cloned["rglob_pattern"]
            vcs_response = cloned["vcs_response"]

            base_directory = Path(vcs_response.dest_dir)

            rules_files = [p for p in base_directory.rglob(rglob_pattern) if p.is_file()]

            rules_count = len(rules_files)
            self.log(f"Enhancing vulnerability data with {rules_count:,d} records from {repo_url}")
            progress = LoopProgress(total_iterations=rules_count, logger=self.log)

            for file_path in progress.iter(rules_files):
                raw_text = file_path.read_text(encoding="utf-8")

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
                    rule_type=DetectionRuleTypes.SURICATA,
                    defaults={
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
