#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import json
import os
from dateutil import parser as dateparser
from unittest.mock import patch
from unittest.mock import MagicMock

from django.test import TestCase

from vulnerabilities import models
from vulnerabilities.import_runner import ImportRunner
from vulnerabilities.importers import DebianDataSource

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/")


class DebianImportTest(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture_path = os.path.join(TEST_DATA, "debian.json")
        with open(fixture_path) as f:
            cls.mock_response = json.load(f)

        cls.importer = models.Importer.objects.create(
            name="debian_unittests",
            license="",
            last_run=dateparser.parse("2019-08-05 13:14:17.733232+05:30"),
            data_source="DebianDataSource",
            data_source_cfg={"debian_tracker_url": "https://security.example.com/json"},
        )
        return super().setUpClass()

    def tearDown(self) -> None:
        self.importer.data_source_cfg = {"debian_tracker_url": "https://security.example.com/json"}
        self.importer.last_run = dateparser.parse("2019-08-05 13:14:17.733232+05:30")
        self.importer.save()

    def test_import(self):
        runner = ImportRunner(self.importer, 5)

        with patch(
            "vulnerabilities.importers.DebianDataSource._fetch", return_value=self.mock_response
        ):
            with patch(
                "vulnerabilities.importers.DebianDataSource.response_is_new", return_value=True
            ):
                runner.run()

        assert models.Vulnerability.objects.count() == 3
        assert models.VulnerabilityReference.objects.count() == 3
        assert (
            models.PackageRelatedVulnerability.objects.count()
            == models.Package.objects.count()
            == 2
        )

        self.assert_for_package("librsync", "0.9.7-10", "jessie", cve_ids={"CVE-2014-8242"})
        self.assert_for_package("librsync", "0.9.7-10", "buster", cve_ids={"CVE-2014-8242"})
        assert models.Vulnerability.objects.filter(vulnerability_id__startswith="TEMP").count() == 0

    def test_response_is_new(self):

        test_data_source = self.importer.make_data_source(batch_size=1)
        mock_resp = MagicMock()
        mock_resp.headers = {"last-modified": "Wed, 05 Aug 2021 09:12:19 GMT"}

        with patch("vulnerabilities.importers.debian.requests.head", return_value=mock_resp):
            assert test_data_source.response_is_new()

        mock_resp.headers = {"last-modified": "Wed, 04 Aug 2019 09:12:19 GMT"}

        with patch("vulnerabilities.importers.debian.requests.head", return_value=mock_resp):
            assert not test_data_source.response_is_new()

    def assert_for_package(self, name, version, release, cve_ids=None):
        qs = models.Package.objects.filter(
            name=name,
            version=version,
            type="deb",
            namespace="debian",
        )
        qs = qs.filter(qualifiers__distro=release)
        assert qs

        if cve_ids:
            assert cve_ids == {v.vulnerability_id for v in qs[0].vulnerabilities.all()}
