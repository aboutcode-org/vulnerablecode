#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import xml.etree.ElementTree as ET

import requests

from vulnerabilities.importer import OvalImporter


class DebianOvalImporter(OvalImporter):
    spdx_license_expression = "LicenseRef-scancode-unknown"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # we could avoid setting translations, and have it
        # set by default in the OvalParser, but we don't yet know
        # whether all OVAL providers use the same format
        self.translations = {"less than": "<"}

    def _fetch(self):
        releases = ["wheezy", "stretch", "jessie", "buster", "bullseye"]
        for release in releases:
            file_url = f"https://www.debian.org/security/oval/oval-definitions-{release}.xml"
            resp = requests.get(file_url).content
            yield (
                {"type": "deb", "namespace": "debian", "qualifiers": {"distro": release}},
                ET.ElementTree(ET.fromstring(resp.decode("utf-8"))),
            )
