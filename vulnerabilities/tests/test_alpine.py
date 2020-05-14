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
import os
from unittest.mock import patch

from django.test import TestCase

from vulnerabilities import models
from vulnerabilities.import_runner import ImportRunner

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, 'test_data/')

MOCK_ADDED_FILES = {os.path.join(TEST_DATA, 'alpine', p) for p in {
    'v3.11/main.yaml',
}}

MOCK_UPDATED_FILES = {os.path.join(TEST_DATA, 'alpine', p) for p in {
    'v3.11/community.yaml',
}}


@patch('vulnerabilities.importers.AlpineDataSource.file_changes', return_value=(MOCK_ADDED_FILES, MOCK_UPDATED_FILES))
@patch('vulnerabilities.importers.AlpineDataSource._ensure_repository')
class AlpineImportTest(TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.importer = models.Importer.objects.create(
            name='alpine_unittests',
            license='',
            last_run=None,
            data_source='AlpineDataSource',
            data_source_cfg={
                'repository_url': 'https://example.com/unit-tests/alpine-secdb',
                'working_directory': os.path.join(TEST_DATA, 'alpine'),
                'create_working_directory': False,
                'remove_working_directory': False,
            },
        )

    @classmethod
    def tearDownClass(cls) -> None:
        pass

    def test_import(self, *_):
        runner = ImportRunner(self.importer, 5)

        runner.run()

        assert models.Vulnerability.objects.count() == 7
        assert models.VulnerabilityReference.objects.count() == 1
        assert models.ResolvedPackage.objects.count() == 8
        assert models.ImpactedPackage.objects.count() == 0

        packages = models.Package.objects.all()
        assert len(packages) == 5

        self.assert_for_package(packages, 'cacti', '1.2.8-r0', cve_ids={'CVE-2019-17358'}, arch='armv7')
        self.assert_for_package(packages, 'cacti', '1.2.8-r0', cve_ids={'CVE-2019-17358'}, arch='x86_64')
        self.assert_for_package(packages, 'xen', '4.12.1-r0', vuln_ref='XSA-295', arch='x86_64')

        self.assert_for_package(packages, 'ansible','2.8.6-r0',
                                cve_ids={'CVE-2019-14846', 'CVE-2019-14856', 'CVE-2019-14858'}, arch='x86_64')

        self.assert_for_package(packages, 'ansible', '2.9.3-r0', cve_ids={'CVE-2019-14904', 'CVE-2019-14905'},
                                arch='x86_64')

    def assert_for_package(self, packages, name, version, cve_ids=None, vuln_ref=None, arch=None):
        qs = packages.filter(name=name, version=version)
        assert qs

        if arch:
            pkg = qs.get(qualifiers__contains=arch)
        else:
            pkg = qs[0]

        qs = models.ResolvedPackage.objects.filter(package=pkg)
        assert qs

        if cve_ids is None and vuln_ref is None:
            return

        vulns = {rp.vulnerability for rp in qs}

        if cve_ids:
            assert cve_ids == {v.cve_id for v in vulns}

        if vuln_ref:
            vuln_refs = set()

            for vuln in vulns:
                vuln_refs.update(
                    {v.reference_id for v in models.VulnerabilityReference.objects.filter(vulnerability=vuln)}
                )

            assert vuln_ref in vuln_refs
