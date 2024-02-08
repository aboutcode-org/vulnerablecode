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


class OpenSSFImporter(Importer):
    license_url = "https://github.com/ossf/malicious-packages/blob/main/LICENSE"
    spdx_license_expression = "CC-BY-4.0"
    url = "git+https://github.com/ossf/malicious-packages"
    importer_name = "OpenSSF Malacious Packages Importer"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        try:
            supported_ecosystems = ["crates.io", "npm", "pypi", "rubygems"]
            self.clone(repo_url=self.url)
            base_path = Path(self.vcs_response.dest_dir)

            for supported_ecosystem in supported_ecosystems:
                path = base_path / "osv" / "malicious" / supported_ecosystem

                for file in path.glob("**/*.json"):
                    try:
                        with open(file) as f:
                            json_data = json.load(f)
                            advisory_url = get_advisory_url(
                                file=file,
                                base_path=base_path,
                                url="https://github.com/ossf/malicious-packages/blob/main",
                            )
                            yield parse_advisory_data(
                                json_data,
                                supported_ecosystem=supported_ecosystem,
                                advisory_url=advisory_url,
                            )
                    except Exception as e:
                        logger.debug(f"Filepath {file} threw an Exception {type(e).__name__} {e!r}")
        finally:
            if self.vcs_response:
                self.vcs_response.delete()
