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
        # base_url = "https://ftp.suse.com/pub/projects/security/oval/"
        page = requests.get(self.base_url).text
        soup = BeautifulSoup(page, "lxml")

        # print(
        #     [
        #         self.base_url + node.get("href")
        #         for node in soup.find_all("a")
        #         if node.get("href").endswith(".gz")
        #     ]
        # )

        suse_oval_files = [
            self.base_url + node.get("href")
            for node in soup.find_all("a")
            if node.get("href").endswith(".gz")
        ]

        # for testfile in suse_oval_files:
        #     print(testfile)

        # Temporary test of .gz version of one of the .xml files we test in test_suse_oval.py:
        # suse_oval_files = [
        #     "https://ftp.suse.com/pub/projects/security/oval/opensuse.leap.micro.5.3.xml.gz"
        # ]

        # TODO: 2023-01-18 Wednesday 18:49:06.  For some reason, if I un-comment the code below, my print above stops working.  Why?

        # for suse_file in suse_oval_files:
        #     # print("suse_file = {}".format(suse_file))
        #     # Do we want to log as ubuntu.py does?  If so, why does debian_oval.py not log?
        #     response = requests.get(suse_file)
        #     # print("\nresponse = {}\n".format(response))

        #     extracted = gzip.decompress(response.content)
        #     # print("\nextracted = {}\n".format(extracted))
        #     yield (
        #         {"type": "rpm", "namespace": "opensuse"},
        #         ET.ElementTree(ET.fromstring(extracted.decode("utf-8"))),
        #     )
