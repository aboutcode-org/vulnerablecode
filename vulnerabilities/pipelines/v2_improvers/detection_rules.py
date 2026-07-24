import json
from pathlib import Path

from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.models import DetectionRule
from vulnerabilities.models import DetectionRuleTypes
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.utils import build_alias_to_advisory_map


class DetectionRulesPipeline(VulnerableCodePipeline):
    """
    Pipeline to collect vulnerability scanner rules (Sigma, YARA, Suricata, ClamAV entries)
    """

    pipeline_id = "detection_rules"
    license_url = "https://github.com/aboutcode-data/detection-rules-collector/blob/master/LICENSE"
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
        return 0

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
                    vulns_id = rule.get("vulnerabilities", [])
                    advisories_map = build_alias_to_advisory_map(vulns_id)
                    advisory_instances = {
                        advisory for adv_list in advisories_map.values() for advisory in adv_list
                    }

                    raw_text = rule.get("rule_text")
                    rule_metadata = rule.get("rule_metadata")
                    detection_rule, _ = DetectionRule.objects.get_or_create(
                        rule_text=raw_text,
                        defaults={
                            "source_url": source_url,
                            "rule_type": rule_type,
                            "rule_metadata": rule_metadata,
                        },
                    )

                    if advisory_instances:
                        detection_rule.related_advisories.add(*advisory_instances)

    def clean_downloads(self):
        """Cleanup any temporary repository data."""
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        """Ensure cleanup is always performed on failure."""
        self.clean_downloads()
