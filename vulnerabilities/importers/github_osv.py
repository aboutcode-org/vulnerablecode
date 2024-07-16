#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import json
import logging
from pathlib import Path
from typing import Iterable

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importers.osv import parse_advisory_data
from vulnerabilities.utils import get_advisory_url

logger = logging.getLogger(__name__)


class GithubOSVImporter(Importer):
    license_url = "https://github.com/github/advisory-database/blob/main/LICENSE.md"
    spdx_license_expression = "CC-BY-4.0"
    repo_url = "git+https://github.com/github/advisory-database/"
    importer_name = "GithubOSV Importer"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        supported_ecosystems = [
            "pypi",
            "npm",
            "maven",
            "golang",
            "composer",
            "hex",
            "gem",
            "nuget",
            "cargo",
        ]
        try:
            self.clone(repo_url=self.repo_url)
            base_path = Path(self.vcs_response.dest_dir)
            # filter out non-github-reviewed files and only keep the files end-with .json
            advisory_dirs = base_path / "advisories/github-reviewed"
            for file in advisory_dirs.glob("**/*.json"):
                advisory_url = get_advisory_url(
                    file=file,
                    base_path=base_path,
                    url="https://github.com/github/advisory-database/blob/main/",
                )
                with open(file) as f:
                    raw_data = json.load(f)
                yield parse_advisory_data(raw_data, supported_ecosystems, advisory_url)
        finally:
            if self.vcs_response:
                self.vcs_response.delete()
