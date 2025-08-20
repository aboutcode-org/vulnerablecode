#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
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


class CVEListV5ImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    pipeline_id = "cvelistv5_importer_v2"
    # license PR: https://github.com/CVEProject/cvelistV5/pull/65
    spdx_license_expression = "CC0-1.0"
    license_url = "https://github.com/CVEProject/cvelistV5/blob/main/LICENSE"
    repo_url = "git+https://github.com/CVEProject/cvelistV5"

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
        vuln_directory = Path(self.vcs_response.dest_dir) / "cves"
        return sum(1 for _ in vuln_directory.glob("*.json"))

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        base_directory = Path(self.vcs_response.dest_dir)
        vulns_directory = base_directory / "cves"

        for file in vulns_directory.rglob("*.json"):
            if not file.name.startswith("CVE-"):
                continue

            advisory_url = get_advisory_url(
                file=file,
                base_path=base_directory,
                url="https://github.com/CVEProject/cvelistV5/blob/main/",
            )

            with open(file) as f:
                raw_data = json.load(f)
            yield parse_cve_v5_advisory(raw_data, advisory_url)

    def clean_downloads(self):
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()
