#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
from pathlib import Path
from typing import Iterable

from fetchcode.vcs import VCSResponse
from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importers.osv_v2 import parse_advisory_data_v3
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import get_advisory_url


class GithubOSVImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    GithubOSV Importer Pipeline

    Collect advisories from the GitHub Advisory Database repository.
    """

    pipeline_id = "github_osv_importer_v2"
    spdx_license_expression = "CC-BY-4.0"
    license_url = "https://github.com/github/advisory-database/blob/main/LICENSE.md"
    repo_url = "git+https://github.com/github/advisory-database/"

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
        advisory_dir = Path(self.vcs_response.dest_dir) / "advisories/github-reviewed"
        return sum(1 for _ in advisory_dir.rglob("*.json"))

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        supported_ecosystems = [
            "pypi",
            "npm",
            "maven",
            # "golang",
            "composer",
            "hex",
            "gem",
            "nuget",
            "cargo",
        ]
        base_path = Path(self.vcs_response.dest_dir)
        advisory_dir = base_path / "advisories/github-reviewed"

        for file in advisory_dir.rglob("*.json"):
            advisory_url = get_advisory_url(
                file=file,
                base_path=base_path,
                url="https://github.com/github/advisory-database/blob/main/",
            )
            with open(file) as f:
                raw_data = json.load(f)
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
