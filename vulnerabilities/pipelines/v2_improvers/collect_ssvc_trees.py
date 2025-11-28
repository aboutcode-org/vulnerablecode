import json
import logging
from pathlib import Path
from typing import Iterable, List

from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.models import SSVC, AdvisoryV2
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import ssvc_calculator

logger = logging.getLogger(__name__)


class CollectSSVCPipeline(VulnerableCodePipeline):
    """
    Collect SSVC Pipeline

    This pipeline collects SSVC from Vulnrichment project and associates them with existing advisories.
    """

    pipeline_id = "collect_ssvc"
    spdx_license_expression = "CC0-1.0"
    license_url = "https://github.com/cisagov/vulnrichment/blob/develop/LICENSE"
    repo_url = "git+https://github.com/cisagov/vulnrichment.git"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_ssvc_data,
            cls.clean_downloads,
        )

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def collect_ssvc_data(self):
        self.log(self.vcs_response.dest_dir)
        base_path = Path(self.vcs_response.dest_dir)
        for file_path in base_path.glob("**/**/*.json"):
            self.log(f"Processing file: {file_path}")
            if not file_path.name.startswith("CVE-"):
                continue
            with open(file_path) as f:
                raw_data = json.load(f)
            file_name = file_path.name
            # strip .json from file name
            cve_id = file_name[:-5]
            advisories = list(AdvisoryV2.objects.filter(advisory_id=cve_id))
            if not advisories:
                self.log(f"No advisories found for CVE ID: {cve_id}")
                continue
            self.parse_cve_advisory(raw_data, advisories)

    def parse_cve_advisory(self, raw_data, advisories: List[AdvisoryV2]):
        self.log(f"Processing CVE data")
        cve_metadata = raw_data.get("cveMetadata", {})
        cve_id = cve_metadata.get("cveId")

        containers = raw_data.get("containers", {})
        adp_data = containers.get("adp", {})
        self.log(f"Processing ADP")

        metrics = [
            adp_metrics for data in adp_data for adp_metrics in data.get("metrics", [])
        ]

        vulnrichment_scoring_system = {
            "other": {
                "ssvc": SCORING_SYSTEMS["ssvc"],
            },  # ignore kev
        }

        for metric in metrics:
            self.log(metric)
            self.log(f"Processing metric")
            for metric_type, metric_value in metric.items():
                if metric_type not in vulnrichment_scoring_system:
                    continue

                if metric_type == "other":
                    other_types = metric_value.get("type")
                    self.log(f"Processing SSVC")
                    if other_types == "ssvc":
                        content = metric_value.get("content", {})
                        options = content.get("options", {})
                        vector_string, decision = ssvc_calculator(content)
                        advisories = list(AdvisoryV2.objects.filter(advisory_id=cve_id))
                        if not advisories:
                            continue
                        ssvc_trees = []
                        for advisory in advisories:
                            obj = SSVC(
                                advisory=advisory,
                                options=options,
                                decision=decision,
                                vector=vector_string,  
                            )
                            ssvc_trees.append(obj)
                        SSVC.objects.bulk_create(ssvc_trees, ignore_conflicts=True, batch_size=1000)

    def clean_downloads(self):
        if self.vcs_response:
            self.log("Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()
