# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an 'AS IS' BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import bz2
from collections import OrderedDict
import json
import os
from unittest import TestCase
from unittest.mock import MagicMock
from unittest.mock import patch

from packageurl import PackageURL

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference
import vulnerabilities.importers.ubuntu_usn as ubuntu_usn


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/", "ubuntu_usn_db", "database-all.json.bz2")


class TestUbuntuUSNDataSource(TestCase):
    @classmethod
    def setUpClass(cls):
        data_src_cfg = {"etags": {}, "db_url": "http://exampledb.com"}
        cls.data_src = ubuntu_usn.UbuntuUSNDataSource(batch_size=1, config=data_src_cfg)
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

    def test_get_purls(self):

        eg_pkg_dict_1 = self.db["763-1"]["releases"]["hardy"]
        eg_pkg_dict_2 = self.db["763-1"]["releases"]["dapper"]
        eg_pkg_dict_3 = self.db["763-1"]["releases"]["intrepid"]

        exp_pkgs_1 = {
            PackageURL(
                type="deb",
                namespace="ubuntu",
                name="xine-lib",
                version="1.1.11.1-1ubuntu3.4",
                qualifiers=OrderedDict(),
                subpath=None,
            ),
            PackageURL(
                type="deb",
                namespace="ubuntu",
                name="libxine1",
                version="1.1.11.1-1ubuntu3.4",
                qualifiers=OrderedDict(),
                subpath=None,
            ),
        }
        exp_pkgs_2 = {
            PackageURL(
                type="deb",
                namespace="ubuntu",
                name="libxine-main1",
                version="1.1.1+ubuntu2-7.12",
                qualifiers=OrderedDict(),
                subpath=None,
            ),
            PackageURL(
                type="deb",
                namespace="ubuntu",
                name="xine-lib",
                version="1.1.1+ubuntu2-7.12",
                qualifiers=OrderedDict(),
                subpath=None,
            ),
        }
        exp_pkgs_3 = {
            PackageURL(
                type="deb",
                namespace="ubuntu",
                name="xine-lib",
                version="1.1.15-0ubuntu3.3",
                qualifiers=OrderedDict(),
                subpath=None,
            ),
            PackageURL(
                type="deb",
                namespace="ubuntu",
                name="libxine1",
                version="1.1.15-0ubuntu3.3",
                qualifiers=OrderedDict(),
                subpath=None,
            ),
        }

        assert exp_pkgs_1 == ubuntu_usn.get_purls(eg_pkg_dict_1)
        assert exp_pkgs_2 == ubuntu_usn.get_purls(eg_pkg_dict_2)
        assert exp_pkgs_3 == ubuntu_usn.get_purls(eg_pkg_dict_3)

    def test_to_advisories(self):

        expected_advisories = [
            Advisory(
                summary="",
                impacted_package_urls=[],
                resolved_package_urls={
                    PackageURL(
                        type="deb",
                        namespace="ubuntu",
                        name="xine-lib",
                        version="1.1.15-0ubuntu3.3",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    ),
                    PackageURL(
                        type="deb",
                        namespace="ubuntu",
                        name="libxine1",
                        version="1.1.15-0ubuntu3.3",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    ),
                },
                references=[
                    Reference(url="https://usn.ubuntu.com/763-1/", reference_id="USN-763-1")
                ],
                vulnerability_id="CVE-2009-0698",
            ),
            Advisory(
                summary="",
                impacted_package_urls=[],
                resolved_package_urls={
                    PackageURL(
                        type="deb",
                        namespace="ubuntu",
                        name="xine-lib",
                        version="1.1.15-0ubuntu3.3",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    ),
                    PackageURL(
                        type="deb",
                        namespace="ubuntu",
                        name="libxine1",
                        version="1.1.15-0ubuntu3.3",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    ),
                },
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
