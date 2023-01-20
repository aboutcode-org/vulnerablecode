#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import gzip
import xml.etree.ElementTree as ET

import requests
from bs4 import BeautifulSoup

from vulnerabilities.importer import OvalImporter


class SuseOvalImporter(OvalImporter):

    spdx_license_expression = "CC-BY-4.0"
    license_url = "https://ftp.suse.com/pub/projects/security/oval/LICENSE"
    base_url = "https://ftp.suse.com/pub/projects/security/oval/"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.translations = {"less than": "<", "equals": "=", "greater than or equal": ">="}

    def _fetch(self):
        page = requests.get(self.base_url).text
        soup = BeautifulSoup(page, "lxml")

        suse_oval_files = [
            self.base_url + node.get("href")
            for node in soup.find_all("a")
            if node.get("href").endswith(".gz")
        ]

        for suse_file in suse_oval_files:
            response = requests.get(suse_file)

            extracted = gzip.decompress(response.content)
            yield (
                {"type": "rpm", "namespace": "opensuse"},
                ET.ElementTree(ET.fromstring(extracted.decode("utf-8"))),
            )
