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

class YaraRulesImproverPipeline(VulnerableCodePipeline):
    repo_url = None
    rglob_patterns = ["**/*.yml"]

    @classmethod
    def steps(cls):
        return (
            cls.clone_repos,
            cls.collect_and_store_rules,
            cls.clean_downloads,
        )

    def clone_repos(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(f"git+{self.repo_url}")

    def collect_and_store_rules(self):
        base_directory = Path(self.vcs_response.dest_dir)
        yara_files = set()
        for pattern in self.rglob_patterns:
            for p in base_directory.glob(pattern):
                if p.is_file():
                    yara_files.add(p)

        rules_count = len(yara_files)
        self.log(f"Processing {rules_count:,d} rules from {self.repo_url}")
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
            raw_text = raw_text.replace("\x00", "")
            rule_url = get_advisory_url(
                file=file_path,
                base_path=base_directory,
                url=f"{self.repo_url}/blob/master/",
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
                rule_type=DetectionRuleTypes.YARA,
                source_url=rule_url,
                defaults={
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


class ProtectionsArtifactsYara(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/elastic/protections-artifacts"
    license_urls = "https://github.com/elastic/protections-artifacts/blob/main/LICENSE.txt"

class YaraRulesYara(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/Yara-Rules/rules"
    license_urls = "https://github.com/Yara-Rules/rules/blob/master/LICENSE"

class XumeiquerForensicsYara(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/Xumeiquer/yara-forensics"
    license_urls = "https://github.com/Xumeiquer/yara-forensics/blob/master/LICENSE"

class ReversinglabsYaraRules(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/reversinglabs/reversinglabs-yara-rules"
    license_urls = "https://github.com/reversinglabs/reversinglabs-yara-rules/blob/develop/LICENSE"

class AdvancedThreatResearchYara(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/advanced-threat-research/Yara-Rules"
    license_urls = "https://github.com/advanced-threat-research/Yara-Rules/blob/master/LICENSE"

class BartblazeYaraRules(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/bartblaze/Yara-rules"
    license_urls = "https://github.com/bartblaze/Yara-rules/blob/master/LICENSE"

class GodaddyYaraRules(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/godaddy/yara-rules"  # archived
    license_urls = "https://github.com/godaddy/yara-rules/blob/master/LICENSE.md"

class SupportIntelligenceIcewaterYara(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/SupportIntelligence/Icewater"
    license_urls = "https://github.com/SupportIntelligence/Icewater/blob/master/LICENSE"

class Jeff0FalltradesSignaturesYara(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/jeFF0Falltrades/YARA-Signatures"
    license_urls = "https://github.com/jeFF0Falltrades/YARA-Signatures/blob/master/LICENSE.md"

class TjnelRepoYara(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/tjnel/yara_repo"
    license_urls = "https://github.com/tjnel/yara_repo/blob/master/LICENSE"

class JpcertccJpcertYara(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/JPCERTCC/jpcert-yara"
    license_urls = "https://github.com/JPCERTCC/jpcert-yara/blob/main/LICENSE"

class MikesxrsOpenSourceYaraRules(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/mikesxrs/Open-Source-YARA-rules"
    license_urls = None

class FboldewinYaraRules(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/fboldewin/YARA-rules"
    license_urls = None

class H3x2bYaraRules(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/h3x2b/yara-rules"
    license_urls = None

class RoadwyDefenderYara(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/roadwy/DefenderYara"
    license_urls = None

class MthchtThreatHuntingKeywordsYara(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/mthcht/ThreatHunting-Keywords-yara-rules"
    license_urls = "https://github.com/mthcht/ThreatHunting-Keywords-yara-rules/blob/main/LICENSE"

class Neo23x0SignatureBaseYara(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/Neo23x0/signature-base"
    license_urls = None

class MalpediaSignatorRulesYara(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/malpedia/signator-rules"
    license_urls = "https://creativecommons.org/licenses/by-sa/4.0/"

class BaderjYara(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/baderj/yara"
    license_urls = "https://github.com/baderj/yara/blob/main/LICENSE"

class DeadbitsYaraRules(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/deadbits/yara-rules"
    license_urls = "https://github.com/deadbits/yara-rules/blob/master/UNLICENSE"

class PmelsonYaraRules(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/pmelson/yara_rules"
    license_urls = None

class SbousseadenYaraHunts(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/sbousseaden/YaraHunts"
    license_urls = None

class EmbeeResearchYaraRules(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/embee-research/Yara-detection-rules"
    license_urls = "https://github.com/embee-research/Yara-detection-rules/tree/main?tab=readme-ov-file#detection-rule-license-drl-11"

class RussianPanda95YaraRules(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/RussianPanda95/Yara-Rules"
    license_urls = None

class AilProjectAilYaraRules(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/ail-project/ail-yara-rules"
    license_urls = "https://github.com/ail-project/ail-yara-rules?tab=AGPL-3.0-1-ov-file"

class MalgamyYaraRules(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/MalGamy/YARA_Rules"
    license_urls = "https://github.com/MalGamy/YARA_Rules/blob/main/LICENSE.md"

class ElceefYaraRulz(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/elceef/yara-rulz"
    license_urls = "https://github.com/elceef/yara-rulz/tree/main?tab=MIT-1-ov-file"

class TenableYaraRules(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/tenable/yara-rules"
    license_urls = "https://github.com/tenable/yara-rules/tree/master?tab=BSD-3-Clause-1-ov-file"

class Dr4k0niaYaraRules(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/dr4k0nia/yara-rules"
    license_urls = "https://github.com/dr4k0nia/yara-rules/blob/main/LICENSE.md"

class Umair9747YaraRules(YaraRulesImproverPipeline):
    repo_urls = "https://github.com/umair9747/yara-rules"
    license_urls = "https://github.com/umair9747/yara-rules?tab=GPL-3.0-1-ov-file"