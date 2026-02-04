#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path
from typing import Iterable

from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipes.osv_v2 import parse_advisory_data_v3
from vulnerabilities.utils import get_advisory_url
from vulnerabilities.utils import load_json


class UbuntuOSVImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Collect Ubuntu OSV format advisories.

    Collect advisories from the GitHub Ubuntu Vulnerability Data repository.
    """

    pipeline_id = "ubuntu_osv_importer_v2"
    spdx_license_expression = "CC-BY-4.0"
    license_url = "https://github.com/canonical/ubuntu-security-notices/blob/main/LICENSE"
    repo_url = "git+https://github.com/canonical/ubuntu-security-notices/"

    progress_step = 1

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
        self.advisories_path = Path(self.vcs_response.dest_dir)

    def advisories_count(self):
        cve_directory = self.advisories_path / "osv" / "cve"
        return sum(1 for _ in cve_directory.rglob("*.json"))

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        supported_ecosystems = ["deb"]
        cve_directory = self.advisories_path / "osv" / "cve"

        for file in cve_directory.rglob("*.json"):
            advisory_url = get_advisory_url(
                file=file,
                base_path=self.advisories_path,
                url="https://github.com/canonical/ubuntu-security-notices/blob/main/",
            )
            raw_data = load_json(file)
            advisory_text = file.read_text()

            yield parse_advisory_data_v3(
                raw_data=raw_data,
                supported_ecosystems=supported_ecosystems,
                advisory_url=advisory_url,
                advisory_text=advisory_text,
            )

    def clean_downloads(self):
        if self.vcs_response:
            self.log("Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()
