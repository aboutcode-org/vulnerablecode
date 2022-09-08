#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import asyncio
import bz2
import logging
import xml.etree.ElementTree as ET

import requests

from vulnerabilities.importer import OvalImporter
from vulnerabilities.package_managers import LaunchpadVersionAPI

logger = logging.getLogger(__name__)


class UbuntuImporter(OvalImporter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # we could avoid setting translations, and have it
        # set by default in the OvalParser, but we don't yet know
        # whether all OVAL providers use the same format
        self.translations = {"less than": "<"}
        self.pkg_manager_api = LaunchpadVersionAPI()

    def _fetch(self):
        base_url = "https://people.canonical.com/~ubuntu-security/oval"
        releases = self.config.releases
        for i, release in enumerate(releases, 1):
            file_url = f"{base_url}/com.ubuntu.{release}.cve.oval.xml.bz2"  # nopep8
            logger.info(f"Fetching Ubuntu Oval: {file_url}")
            response = requests.get(file_url)
            if response.status_code != requests.codes.ok:
                logger.error(
                    f"Failed to fetch Ubuntu Oval: HTTP {response.status_code} : {file_url}"
                )
                continue

            extracted = bz2.decompress(response.content)
            yield (
                {"type": "deb", "namespace": "ubuntu"},
                ET.ElementTree(ET.fromstring(extracted.decode("utf-8"))),
            )

        logger.info(f"Fetched {i} Ubuntu Oval releases from {base_url}")

    def set_api(self, packages):
        asyncio.run(self.pkg_manager_api.load_api(packages))
