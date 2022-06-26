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
        for file in fork_and_get_files(self.url):
            yield parse_advisory_data(file, supported_ecosystem='pypi')


class ForkError(Exception):
    pass


def fork_and_get_files(url) -> dict:
    """
    Fetch the github repository and go to vulns directory ,
    then open directories one by one and return a file .
    """
    try:
        fork_directory = fetch_via_git(url=url)
    except Exception as e:
        logger.error(f"Can't clone url {url}")
        raise ForkError(url) from e

    advisory_dirs = os.path.join(fork_directory.dest_dir, "vulns")
    for root, _, files in os.walk(advisory_dirs):
        for file in files:
            if not file.endswith(".yaml"):
                logger.warning(f"unsupported file {file}")
            else:
                with open(os.path.join(root, file), "r") as f:
                    yield saneyaml.load(f.read())
