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

import saneyaml
from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipes.osv_v2 import parse_advisory_data_v3
from vulnerabilities.utils import get_advisory_url


class PyPaImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Pypa Importer Pipeline

    Collect advisories from PyPA GitHub repository."""

    pipeline_id = "pypa_importer_v2"
    spdx_license_expression = "CC-BY-4.0"
    license_url = "https://github.com/pypa/advisory-database/blob/main/LICENSE"
    repo_url = "git+https://github.com/pypa/advisory-database"
    precedence = 200

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
        vulns_directory = Path(self.vcs_response.dest_dir) / "vulns"
        return sum(1 for _ in vulns_directory.rglob("*.yaml"))

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        base_directory = Path(self.vcs_response.dest_dir)
        vulns_directory = base_directory / "vulns"

        for advisory in vulns_directory.rglob("*.yaml"):
            advisory_url = get_advisory_url(
                file=advisory,
                base_path=base_directory,
                url="https://github.com/pypa/advisory-database/blob/main/",
            )
            advisory_text = advisory.read_text()
            advisory_dict = saneyaml.load(advisory_text)
            yield parse_advisory_data_v3(
                raw_data=advisory_dict,
                supported_ecosystems=["pypi"],
                advisory_url=advisory_url,
                advisory_text=advisory_text,
            )

    def clean_downloads(self):
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()
