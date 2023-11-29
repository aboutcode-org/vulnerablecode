#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import logging
import os
from pathlib import Path
from typing import Iterable

import saneyaml

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importers.osv import parse_advisory_data

logger = logging.getLogger(__name__)


class PyPaImporter(Importer):
    license_url = "https://github.com/pypa/advisory-database/blob/main/LICENSE"
    spdx_license_expression = "CC-BY-4.0"
    repo_url = "git+https://github.com/pypa/advisory-database"
    importer_name = "pypa"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        try:
            vcs_response = self.clone(repo_url=self.repo_url)
            path = Path(vcs_response.dest_dir)
            for relative_path, raw_data in fork_and_get_files(base_path=path):
                yield parse_advisory_data(
                    raw_data=raw_data,
                    supported_ecosystem="pypi",
                    advisory_url=f"https://github.com/pypa/advisory-database/blob/main/{relative_path}",
                )
        finally:
            if self.vcs_response:
                self.vcs_response.delete()


class ForkError(Exception):
    pass


def fork_and_get_files(base_path) -> dict:
    """
    Yield advisorie data mappings from the PyPA GitHub repository at ``url``.
    """
    advisory_dirs = os.path.join(base_path, "vulns")
    for root, _, files in os.walk(advisory_dirs):
        for file in files:
            path = os.path.join(root, file)
            if not file.endswith(".yaml"):
                logger.warning(f"Unsupported non-YAML PyPA advisory file: {path}")
                continue
            relative_path = str(Path(path).relative_to(base_path)).strip("/")
            with open(path) as f:
                yield relative_path, saneyaml.load(f.read())
