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
    rglob_patterns = [
        "**/*.yara",
        "**/*.yar",
    ]

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
    pipeline_id = "elastic-protections-artifacts"
    repo_url = "https://github.com/elastic/protections-artifacts"
    license_url = "https://github.com/elastic/protections-artifacts/blob/main/LICENSE.txt"
    rglob_patterns = ["yara/rules/**/*.yar"]

class YaraRulesYara(YaraRulesImproverPipeline):
    pipeline_id = "yara-rules-rules"
    repo_url = "https://github.com/Yara-Rules/rules"
    license_url = "https://github.com/Yara-Rules/rules/blob/master/LICENSE"
    rglob_patterns = [
        "antidebug_antivm/**/*.yar",
        "capabilities/**/*.yar",
        "crypto/**/*.yar",
        "cve_rules/**/*.yar",
        "deprecated/**/*.yar",
        "email/**/*.yar",
        "exploit_kits/**/*.yar",
        "maldocs/**/*.yar",
        "malware/**/*.yar",
        "mobile_malware/**/*.yar",
        "packers/**/*.yar",
        "utils/**/*.yar",
        "webshells/**/*.yar",
    ]

class XumeiquerForensicsYara(YaraRulesImproverPipeline):
    pipeline_id = "xumeiquer-yara-forensics"
    repo_url = "https://github.com/Xumeiquer/yara-forensics"
    license_url = "https://github.com/Xumeiquer/yara-forensics/blob/master/LICENSE"

class ReversinglabsYaraRules(YaraRulesImproverPipeline):
    pipeline_id = "reversinglabs-yara-rules"
    repo_url = "https://github.com/reversinglabs/reversinglabs-yara-rules"
    license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules/blob/develop/LICENSE"

class AdvancedThreatResearchYara(YaraRulesImproverPipeline):
    pipeline_id = "advanced-threat-research-yara-rules"
    repo_url = "https://github.com/advanced-threat-research/Yara-Rules"
    license_url = "https://github.com/advanced-threat-research/Yara-Rules/blob/master/LICENSE"

class BartblazeYaraRules(YaraRulesImproverPipeline):
    pipeline_id = "bartblaze-yara-rules"
    repo_url = "https://github.com/bartblaze/Yara-rules"
    license_url = "https://github.com/bartblaze/Yara-rules/blob/master/LICENSE"

class GodaddyYaraRules(YaraRulesImproverPipeline):
    pipeline_id = "godaddy-yara-rules"
    repo_url = "https://github.com/godaddy/yara-rules"  # archived
    license_url = "https://github.com/godaddy/yara-rules/blob/master/LICENSE.md"

class SupportIntelligenceIcewaterYara(YaraRulesImproverPipeline):
    pipeline_id = "supportintelligence-icewater"
    repo_url = "https://github.com/SupportIntelligence/Icewater"
    license_url = "https://github.com/SupportIntelligence/Icewater/blob/master/LICENSE"

class Jeff0FalltradesSignaturesYara(YaraRulesImproverPipeline):
    pipeline_id = "jeff0falltrades-yara-signatures"
    repo_url = "https://github.com/jeFF0Falltrades/YARA-Signatures"
    license_url = "https://github.com/jeFF0Falltrades/YARA-Signatures/blob/master/LICENSE.md"

class TjnelRepoYara(YaraRulesImproverPipeline):
    pipeline_id = "tjnel-yara-repo"
    repo_url = "https://github.com/tjnel/yara_repo"
    license_url = "https://github.com/tjnel/yara_repo/blob/master/LICENSE"

class JpcertccJpcertYara(YaraRulesImproverPipeline):
    pipeline_id = "jpcertcc-jpcert-yara"
    repo_url = "https://github.com/JPCERTCC/jpcert-yara"
    license_url = "https://github.com/JPCERTCC/jpcert-yara/blob/main/LICENSE"

class MikesxrsOpenSourceYaraRules(YaraRulesImproverPipeline):
    pipeline_id = "mikesxrs-open-source-yara-rules"
    repo_url = "https://github.com/mikesxrs/Open-Source-YARA-rules"
    license_url = None

class FboldewinYaraRules(YaraRulesImproverPipeline):
    pipeline_id = "fboldewin-yara-rules"
    repo_url = "https://github.com/fboldewin/YARA-rules"
    license_url = None

class H3x2bYaraRules(YaraRulesImproverPipeline):
    pipeline_id = "h3x2b-yara-rules"
    repo_url = "https://github.com/h3x2b/yara-rules"
    license_url = None

class RoadwyDefenderYara(YaraRulesImproverPipeline):
    pipeline_id = "roadwy-defenderyara"
    repo_url = "https://github.com/roadwy/DefenderYara"
    license_url = None

class MthchtThreatHuntingKeywordsYara(YaraRulesImproverPipeline):
    pipeline_id = "mthcht-threathunting-keywords-yara-rules"
    repo_url = "https://github.com/mthcht/ThreatHunting-Keywords-yara-rules"
    license_url = "https://github.com/mthcht/ThreatHunting-Keywords-yara-rules/blob/main/LICENSE"

class Neo23x0SignatureBaseYara(YaraRulesImproverPipeline):
    pipeline_id = "neo23x0-signature-base"
    repo_url = "https://github.com/Neo23x0/signature-base"
    license_url = None

class MalpediaSignatorRulesYara(YaraRulesImproverPipeline):
    pipeline_id = "malpedia-signator-rules"
    repo_url = "https://github.com/malpedia/signator-rules"
    license_url = "https://creativecommons.org/licenses/by-sa/4.0/"

class BaderjYara(YaraRulesImproverPipeline):
    pipeline_id = "baderj-yara"
    repo_url = "https://github.com/baderj/yara"
    license_url = "https://github.com/baderj/yara/blob/main/LICENSE"

class DeadbitsYaraRules(YaraRulesImproverPipeline):
    pipeline_id = "deadbits-yara-rules"
    repo_url = "https://github.com/deadbits/yara-rules"
    license_url = "https://github.com/deadbits/yara-rules/blob/master/UNLICENSE"

class PmelsonYaraRules(YaraRulesImproverPipeline):
    pipeline_id = "pmelson-yara-rules"
    repo_url = "https://github.com/pmelson/yara_rules"
    license_url = None

class SbousseadenYaraHunts(YaraRulesImproverPipeline):
    pipeline_id = "sbousseaden-yarahunts"
    repo_url = "https://github.com/sbousseaden/YaraHunts"
    license_url = None

class EmbeeResearchYaraRules(YaraRulesImproverPipeline):
    pipeline_id = "embee-research-yara-detection-rules"
    repo_url = "https://github.com/embee-research/Yara-detection-rules"
    license_url = "https://github.com/embee-research/Yara-detection-rules/tree/main?tab=readme-ov-file#detection-rule-license-drl-11"

class RussianPanda95YaraRules(YaraRulesImproverPipeline):
    pipeline_id = "russianpanda95-yara-rules"
    repo_url = "https://github.com/RussianPanda95/Yara-Rules"
    license_url = None

class AilProjectAilYaraRules(YaraRulesImproverPipeline):
    pipeline_id = "ail-project-ail-yara-rules"
    repo_url = "https://github.com/ail-project/ail-yara-rules"
    license_url = "https://github.com/ail-project/ail-yara-rules?tab=AGPL-3.0-1-ov-file"

class MalgamyYaraRules(YaraRulesImproverPipeline):
    pipeline_id = "malgamy-yara-rules"
    repo_url = "https://github.com/MalGamy/YARA_Rules"
    license_url = "https://github.com/MalGamy/YARA_Rules/blob/main/LICENSE.md"

class ElceefYaraRulz(YaraRulesImproverPipeline):
    pipeline_id = "elceef-yara-rulz"
    repo_url = "https://github.com/elceef/yara-rulz"
    license_url = "https://github.com/elceef/yara-rulz/tree/main?tab=MIT-1-ov-file"

class TenableYaraRules(YaraRulesImproverPipeline):
    pipeline_id = "tenable-yara-rules"
    repo_url = "https://github.com/tenable/yara-rules"
    license_url = "https://github.com/tenable/yara-rules/tree/master?tab=BSD-3-Clause-1-ov-file"

class Dr4k0niaYaraRules(YaraRulesImproverPipeline):
    pipeline_id = "dr4k0nia-yara-rules"
    repo_url = "https://github.com/dr4k0nia/yara-rules"
    license_url = "https://github.com/dr4k0nia/yara-rules/blob/main/LICENSE.md"

class Umair9747YaraRules(YaraRulesImproverPipeline):
    pipeline_id = "umair9747-yara-rules"
    repo_url = "https://github.com/umair9747/yara-rules"
    license_url = "https://github.com/umair9747/yara-rules?tab=GPL-3.0-1-ov-file"