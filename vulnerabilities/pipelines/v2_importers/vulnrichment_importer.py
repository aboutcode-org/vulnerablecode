import json
import logging
from pathlib import Path
from typing import Iterable

from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importers.cve_schema import parse_cve_v5_advisory
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import get_advisory_url

logger = logging.getLogger(__name__)


class VulnrichImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Vulnrichment Importer Pipeline

    This pipeline imports security advisories from Vulnrichment project.
    """

    pipeline_id = "vulnrichment_importer_v2"
    spdx_license_expression = "CC0-1.0"
    license_url = "https://github.com/cisagov/vulnrichment/blob/develop/LICENSE"
    repo_url = "git+https://github.com/cisagov/vulnrichment.git"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def advisories_count(self):
        vuln_directory = Path(self.vcs_response.dest_dir)
        return sum(1 for _ in vuln_directory.glob("*.json"))

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        base_path = Path(self.vcs_response.dest_dir)
        for file_path in base_path.glob("**/**/*.json"):
            if not file_path.name.startswith("CVE-"):
                continue
            with open(file_path) as f:
                raw_data = json.load(f)
            advisory_url = get_advisory_url(
                file=file_path,
                base_path=base_path,
                url="https://github.com/cisagov/vulnrichment/blob/develop/",
            )
            yield parse_cve_v5_advisory(raw_data, advisory_url)

    def clean_downloads(self):
        if self.vcs_response:
            self.log("Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()
