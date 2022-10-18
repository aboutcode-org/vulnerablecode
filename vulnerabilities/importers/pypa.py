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
from typing import Iterable

import saneyaml
from fetchcode.vcs.git import fetch_via_git

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importers.osv import parse_advisory_data

logger = logging.getLogger(__name__)


class PyPaImporter(Importer):
    license_url = "https://github.com/pypa/advisory-database/blob/main/LICENSE"
    spdx_license_expression = "CC-BY-4.0"
    url = "git+https://github.com/pypa/advisory-database"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        for raw_data in fork_and_get_files(self.url):
            yield parse_advisory_data(raw_data=raw_data, supported_ecosystem="pypi")


class ForkError(Exception):
    pass


def fork_and_get_files(url) -> dict:
    """
    Yield advisorie data mappings from the PyPA GitHub repository at ``url``.
    """
    try:
        fork_directory = fetch_via_git(url=url)
    except Exception as e:
        logger.error(f"Failed to clone url {url}: {e}")
        raise ForkError(url) from e

    advisory_dirs = os.path.join(fork_directory.dest_dir, "vulns")
    for root, _, files in os.walk(advisory_dirs):
        for file in files:
            path = os.path.join(root, file)
            if not file.endswith(".yaml"):
                logger.warning(f"Unsupported non-YAML PyPA advisory file: {path}")
                continue
            with open(path) as f:
                yield saneyaml.load(f.read())
