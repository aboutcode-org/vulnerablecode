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

from vulnerabilities.models import DetectionRule
from vulnerabilities.models import DetectionRuleTypes
from vulnerabilities.pipelines import VulnerableCodePipeline


class YaraRulesImproverPipeline(VulnerableCodePipeline):
    pipeline_id = "yara_rules"

    repo_urls = [
        "git+https://github.com/elastic/protections-artifacts",
        "git+https://github.com/Yara-Rules/rules",
        "git+https://github.com/Xumeiquer/yara-forensics",
        "git+https://github.com/reversinglabs/reversinglabs-yara-rules",
        "git+https://github.com/advanced-threat-research/Yara-Rules",
        "git+https://github.com/bartblaze/Yara-rules",
        "git+https://github.com/godaddy/yara-rules",  # archived
        "git+https://github.com/SupportIntelligence/Icewater",
        "git+https://github.com/jeFF0Falltrades/YARA-Signatures",
        "git+https://github.com/tjnel/yara_repo",
        "git+https://github.com/JPCERTCC/jpcert-yara",
        "git+https://github.com/mikesxrs/Open-Source-YARA-rules",
        "git+https://github.com/fboldewin/YARA-rules",
        "git+https://github.com/h3x2b/yara-rules",
    ]

    license_urls = """
    https://github.com/elastic/protections-artifacts/blob/main/LICENSE.txt
    https://github.com/Yara-Rules/rules/blob/master/LICENSE
    https://github.com/Xumeiquer/yara-forensics/blob/master/LICENSE
    https://github.com/reversinglabs/reversinglabs-yara-rules/blob/develop/LICENSE
    https://github.com/advanced-threat-research/Yara-Rules/blob/master/LICENSE
    https://github.com/bartblaze/Yara-rules/blob/master/LICENSE
    https://github.com/godaddy/yara-rules/blob/master/LICENSE.md
    https://github.com/SupportIntelligence/Icewater/blob/master/LICENSE
    https://github.com/jeFF0Falltrades/YARA-Signatures/blob/master/LICENSE.md
    https://github.com/tjnel/yara_repo/blob/master/LICENSE
    https://github.com/JPCERTCC/jpcert-yara/blob/main/LICENSE
        
    NO-LICENSE: https://github.com/mikesxrs/Open-Source-YARA-rules/
    NO-LICENSE: https://github.com/fboldewin/YARA-rules
    NO-LICENSE: https://github.com/h3x2b/yara-rules
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.vcs_responses = []

    @classmethod
    def steps(cls):
        return (
            cls.clone_repos,
            cls.collect_and_store_rules,
            cls.clean_downloads,
        )

    def clone_repos(self):
        for url in self.repo_urls:
            self.log(f"Cloning `{url}`")
            try:
                response = fetch_via_vcs(url)
                if response:
                    self.vcs_responses.append((response, url))
            except Exception as e:
                self.log(f"Failed to clone {url}: {e}")

    def collect_and_store_rules(self):
        for vcs_response, repo_url in self.vcs_responses:
            base_directory = Path(vcs_response.dest_dir)
            yara_files = [
                p
                for p in base_directory.rglob("*")
                if p.suffix in (".yar", ".yara") and p.is_file()
            ]

            rules_count = len(yara_files)
            self.log(f"Processing {rules_count:,d} rules from {repo_url}")

            progress = LoopProgress(total_iterations=rules_count, logger=self.log)
            for file_path in progress.iter(yara_files):
                if not file_path.exists() or not file_path.is_file():
                    self.log(
                        f"Skipping file as it no longer exists or is not a file: {file_path}",
                        level="warning",
                    )
                    continue

                raw_text = file_path.read_text(encoding="utf-8", errors="ignore")
                if not raw_text:
                    continue

                DetectionRule.objects.update_or_create(
                    rule_text=raw_text,
                    rule_type=DetectionRuleTypes.YARA,
                    advisory=None,
                )

    def clean_downloads(self):
        for vcs_response, _ in self.vcs_responses:
            if vcs_response:
                self.log(f"Removing cloned repository: {vcs_response.dest_dir}")
                vcs_response.delete()

        self.vcs_responses = []

    def on_failure(self):
        self.clean_downloads()
