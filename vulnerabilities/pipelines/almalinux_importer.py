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
from vulnerabilities.importers.osv import parse_advisory_data
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline
from vulnerabilities.utils import get_advisory_url

logger = logging.getLogger(__name__)


class AlmalinuxImporterPipeline(VulnerableCodeBaseImporterPipeline):
    """Collect Almalinux advisories."""

    pipeline_id = "almalinux_importer"
    spdx_license_expression = "MIT"
    license_url = "https://github.com/AlmaLinux/osv-database/blob/master/LICENSE"
    importer_name = "Almalinux Importer"
    repo_url = "git+https://github.com/AlmaLinux/osv-database"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.import_new_advisories,
            cls.clean_downloads,
        )

    def clone(self):
        self.log(f"Cloning `{self.repo_url}")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def advisories_count(self):
        vuln_directory = Path(self.vcs_response.dest_dir) / "advisories"
        return len(list(vuln_directory.rglob("*.json")))

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        base_directory = Path(self.vcs_response.dest_dir)
        vuln_directory = base_directory / "advisories"

        for file in vuln_directory.rglob("*.json"):
            advisory_url = get_advisory_url(
                file=file,
                base_path=base_directory,
                url="https://github.com/AlmaLinux/osv-database/blob/master/",
            )
            with open(file) as f:
                raw_data = json.load(f)
            yield parse_advisory_data(
                raw_data=raw_data, supported_ecosystems=["rpm"], advisory_url=advisory_url
            )

    def clean_downloads(self):
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()
