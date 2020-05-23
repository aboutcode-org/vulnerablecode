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
from unittest.mock import patch

from django.test import TestCase

from vulnerabilities import models
from vulnerabilities.import_runner import ImportRunner

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, 'test_data/')


class ArchlinuxImportTest(TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        fixture_path = os.path.join(TEST_DATA, 'archlinux.json')
        with open(fixture_path) as f:
            cls.mock_response = json.load(f)

        cls.importer = models.Importer.objects.create(
            name='archlinux_unittests',
            license='',
            last_run=None,
            data_source='ArchlinuxDataSource',
            data_source_cfg={
                'archlinux_tracker_url': 'https://security.example.com/json',
            },
        )

    @classmethod
    def tearDownClass(cls) -> None:
        pass

    def test_import(self):
        runner = ImportRunner(self.importer, 5)

        with patch(
                'vulnerabilities.importers.ArchlinuxDataSource._fetch',
                return_value=self.mock_response
        ):
            runner.run()

        assert models.Vulnerability.objects.count() == 6
        assert models.VulnerabilityReference.objects.count() == 4
        assert models.ImpactedPackage.objects.count() == 12
        assert models.ResolvedPackage.objects.count() == 8
        assert models.Package.objects.count() == 10

        self.assert_for_package(
            'squid',
            '4.10-2',
            cve_ids={'CVE-2020-11945', 'CVE-2019-12521', 'CVE-2019-12519'},
        )
        self.assert_for_package('openconnect', '1:8.05-1', cve_ids={'CVE-2020-12823'})
        self.assert_for_package(
            'wireshark-common',
            '2.6.0-1',
            cve_ids={'CVE-2018-11362', 'CVE-2018-11361'},
        )
        self.assert_for_package(
            'wireshark-gtk',
            '2.6.0-1',
            cve_ids={'CVE-2018-11362', 'CVE-2018-11361'},
        )
        self.assert_for_package(
            'wireshark-cli',
            '2.6.0-1',
            cve_ids={'CVE-2018-11362', 'CVE-2018-11361'},
        )
        self.assert_for_package(
            'wireshark-qt',
            '2.6.0-1',
            cve_ids={'CVE-2018-11362', 'CVE-2018-11361'},
        )
        self.assert_for_package('wireshark-common', '2.6.1-1')
        self.assert_for_package('wireshark-gtk', '2.6.1-1')
        self.assert_for_package('wireshark-cli', '2.6.1-1')
        self.assert_for_package('wireshark-qt', '2.6.1-1')

    def assert_for_package(self, name, version, cve_ids=None):
        qs = models.Package.objects.filter(
            name=name,
            version=version,
            type='pacman',
            namespace='archlinux',
        )
        assert qs

        if cve_ids:
            assert cve_ids == {v.cve_id for v in qs[0].vulnerabilities.all()}
