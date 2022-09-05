#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import logging
from pathlib import Path
from typing import Iterable

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import GitImporter
from vulnerabilities.importers.osv import parse_advisory_data
from vulnerabilities.utils import load_json

logger = logging.getLogger(__name__)


class GithubOSVImporter(GitImporter):
    license_url = "https://github.com/github/advisory-database/blob/main/LICENSE.md"
    spdx_license_expression = "CC-BY-4.0"

    def __init__(self):
        super().__init__(repo_url="git+https://github.com/github/advisory-database")

    def advisory_data(self) -> Iterable[AdvisoryData]:
        try:
            self.clone()
            path = Path(self.vcs_response.dest_dir)

            glob = "**/*.json"
            files = (p for p in path.glob(glob) if p.is_file())
            for file in files:
                raw_data = load_json(file)
                yield parse_advisory_data(raw_data, supported_ecosystem="pypi")
        finally:
            if self.vcs_response:
                self.vcs_response.delete()

