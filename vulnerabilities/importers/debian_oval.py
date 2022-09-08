#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import asyncio
import xml.etree.ElementTree as ET

import requests

from vulnerabilities.importer import OvalImporter
from vulnerabilities.package_managers import DebianVersionAPI
from vulnerabilities.utils import create_etag


class DebianOvalImporter(OvalImporter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # we could avoid setting translations, and have it
        # set by default in the OvalParser, but we don't yet know
        # whether all OVAL providers use the same format
        self.translations = {"less than": "<"}
        self.pkg_manager_api = DebianVersionAPI()

    def _fetch(self):
        releases = self.config.releases
        for release in releases:
            file_url = f"https://www.debian.org/security/oval/oval-definitions-{release}.xml"
            if not create_etag(data_src=self, url=file_url, etag_key="ETag"):
                continue

            resp = requests.get(file_url).content
            yield (
                {"type": "deb", "namespace": "debian", "qualifiers": {"distro": release}},
                ET.ElementTree(ET.fromstring(resp.decode("utf-8"))),
            )
        return []

    def set_api(self, packages):
        asyncio.run(self.pkg_manager_api.load_api(packages))
