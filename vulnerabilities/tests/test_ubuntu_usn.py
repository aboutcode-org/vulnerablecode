#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import bz2
import json
import os
from collections import OrderedDict
from unittest import TestCase
from unittest.mock import MagicMock
from unittest.mock import patch

from packageurl import PackageURL

import vulnerabilities.importers.ubuntu_usn as ubuntu_usn
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Reference

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/", "ubuntu_usn_db", "database-all.json.bz2")


class TestUbuntuUSNImporter(TestCase):
    @classmethod
    def setUpClass(cls):
        data_src_cfg = {"etags": {}, "db_url": "http://exampledb.com"}
        cls.data_src = ubuntu_usn.UbuntuUSNImporter(batch_size=1, config=data_src_cfg)
        with open(TEST_DATA, "rb") as f:
            cls.raw_data = f.read()
            cls.db = json.loads(bz2.decompress(cls.raw_data))

    def test_get_usn_references(self):

        eg_usn = "435-1"
        expected_references = Reference(
            reference_id="USN-435-1", url="https://usn.ubuntu.com/435-1/"
        )

        found_references = ubuntu_usn.get_usn_references(eg_usn)
        assert found_references == expected_references

    def test_fetch(self):

        mock_response = MagicMock()
        mock_response.content = self.raw_data
        with patch("vulnerabilities.importers.ubuntu_usn.requests.get", return_value=mock_response):
            assert ubuntu_usn.fetch("www.db.com") == self.db

    def test_to_advisories(self):

        expected_advisories = [
            Advisory(
                summary="",
                references=[
                    Reference(url="https://usn.ubuntu.com/763-1/", reference_id="USN-763-1")
                ],
                vulnerability_id="CVE-2009-0698",
            ),
            Advisory(
                summary="",
                references=[
                    Reference(url="https://usn.ubuntu.com/763-1/", reference_id="USN-763-1")
                ],
                vulnerability_id="CVE-2009-1274",
            ),
        ]
        found_advisories = self.data_src.to_advisories(self.db)

        found_advisories = list(map(Advisory.normalized, found_advisories))
        expected_advisories = list(map(Advisory.normalized, expected_advisories))
        assert sorted(found_advisories) == sorted(expected_advisories)

    def test_create_etag(self):
        assert self.data_src.config.etags == {}

        mock_response = MagicMock()
        mock_response.headers = {"etag": "2131151243&2191"}

        with patch("vulnerabilities.importers.ubuntu.requests.head", return_value=mock_response):
            assert self.data_src.create_etag("https://example.org")
            assert self.data_src.config.etags == {"https://example.org": "2131151243&2191"}
            assert not self.data_src.create_etag("https://example.org")
