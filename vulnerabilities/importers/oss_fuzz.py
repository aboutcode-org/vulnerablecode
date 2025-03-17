#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import logging
from pathlib import Path
from typing import Iterable

import saneyaml

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importers.osv import parse_advisory_data
from vulnerabilities.utils import get_advisory_url

logger = logging.getLogger(__name__)


class OSSFuzzImporter(Importer):
    license_url = "https://github.com/google/oss-fuzz-vulns/blob/main/LICENSE"
    spdx_license_expression = "CC-BY-4.0"
    url = "git+https://github.com/google/oss-fuzz-vulns"
    importer_name = "OSS Fuzz Importer"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        try:
            self.clone(repo_url=self.url)
            base_path = Path(self.vcs_response.dest_dir)
            path = base_path / "vulns"
            for file in path.glob("**/*.yaml"):
                with open(file) as f:
                    yaml_data = saneyaml.load(f.read())
                    advisory_url = get_advisory_url(
                        file=file,
                        base_path=base_path,
                        url="https://github.com/pypa/advisory-database/blob/main/",
                    )
                    yield parse_advisory_data(
                        yaml_data, supported_ecosystems=["oss-fuzz"], advisory_url=advisory_url
                    )
        finally:
            if self.vcs_response:
                self.vcs_response.delete()
