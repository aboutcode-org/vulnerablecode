#
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
from typing import Any
from typing import Iterable

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importers.osv import parse_advisory_data
from vulnerabilities.utils import get_advisory_url

LOGGER = logging.getLogger(__name__)
BASE_URL = "https://github.com/AlmaLinux/osv-database"


class AlmaImporter(Importer):
    spdx_license_expression = "MIT License"
    license_url = "https://github.com/AlmaLinux/osv-database/blob/master/LICENSE"
    importer_name = "Alma Linux Importer"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        supported_ecosystems = ["almalinux:8", "almalinux:9"]
        try:
            self.clone(repo_url=self.BASE_URL)
            base_path = Path(self.vcs_response.dest_dir)
            advisory_dirs = base_path / "tree/master/advisories"
            # Iterate throught the directories in the repo and get the .json files
            for file in advisory_dirs.glob("**/*.json"):
                advisory_url = get_advisory_url(
                    file=file,
                    base_path=base_path,
                    url="https://github.com/AlmaLinux/osv-database/blob/master",
                )
                with open(file) as f:
                    raw_data = json.load(f)
                yield parse_advisory_data(raw_data, supported_ecosystems, advisory_url)
        finally:
            if self.vcs_response:
                self.vcs_response.delete()
