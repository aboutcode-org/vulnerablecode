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

import saneyaml

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importers.osv import parse_advisory_data

logger = logging.getLogger(__name__)


class OSSFuzzImporter(Importer):
    license_url = "https://github.com/google/oss-fuzz-vulns/blob/main/LICENSE"
    spdx_license_expression = "CC-BY-4.0"
    url = "git+https://github.com/google/oss-fuzz-vulns"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        try:
            self.clone(repo_url=self.url)
            path = Path(self.vcs_response.dest_dir) / "vulns"
            for file in path.glob("**/*.yaml"):
                with open(file) as f:
                    yaml_data = saneyaml.load(f.read())
                    yield parse_advisory_data(yaml_data, supported_ecosystem="oss-fuzz")
        finally:
            if self.vcs_response:
                self.vcs_response.delete()
