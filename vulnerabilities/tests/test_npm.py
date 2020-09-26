# Author: Navonil Das (@NavonilDas)
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
import shutil
import tempfile
from unittest.mock import patch
import zipfile

from django.test import TestCase

from vulnerabilities import models
from vulnerabilities.import_runner import ImportRunner
from vulnerabilities.package_managers import NpmVersionAPI
from vulnerabilities.importers.npm import categorize_versions

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, 'test_data/')


MOCK_VERSION_API = NpmVersionAPI(cache={
    'jquery': {'3.4', '3.8'},
    'kerberos': {'0.5.8', '1.2'},
    '@hapi/subtext': {'3.7', '4.1.1', '6.1.3', '7.0.0', '7.0.5'},
})


@patch('vulnerabilities.importers.NpmDataSource._update_from_remote')
class NpmImportTest(TestCase):

    tempdir = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.tempdir = tempfile.mkdtemp()
        zip_path = os.path.join(TEST_DATA, 'npm.zip')

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(cls.tempdir)

        cls.importer = models.Importer.objects.create(
            name='npm_unittests',
            license='',
            last_run=None,
            data_source='NpmDataSource',
            data_source_cfg={
                'repository_url': 'https://example.git',
                'working_directory': os.path.join(cls.tempdir, 'npm_test'),
                'create_working_directory': False,
                'remove_working_directory': False
            }
        )

    @classmethod
    def tearDownClass(cls) -> None:
        # Make sure no requests for unexpected package names have been made during the tests.
        shutil.rmtree(cls.tempdir)
        assert len(MOCK_VERSION_API.cache) == 3, MOCK_VERSION_API.cache

    def test_import(self, _):
        runner = ImportRunner(self.importer, 5)

        with patch('vulnerabilities.importers.NpmDataSource.versions', new=MOCK_VERSION_API):
            with patch('vulnerabilities.importers.NpmDataSource.set_api'):
                runner.run()

        assert models.Vulnerability.objects.count() == 3
        assert models.VulnerabilityReference.objects.count() == 3
        assert models.PackageRelatedVulnerability.objects.filter(
            is_vulnerable=False).count() == 5

        assert models.PackageRelatedVulnerability.objects.filter(
            is_vulnerable=True).count() == 4

        expected_package_count = sum([len(v) for v in MOCK_VERSION_API.cache.values()])
        assert models.Package.objects.count() == expected_package_count

        self.assert_for_package('jquery', {'3.4'}, {'3.8'}, '1518', identifier='CVE-2020-11022')
        self.assert_for_package('kerberos', {'0.5.8'}, {'1.2'}, '1514')
        self.assert_for_package('subtext', {'4.1.1', '7.0.0'}, {'3.7', '6.1.3', '7.0.5'}, '1476')

    def assert_for_package(
            self,
            package_name,
            impacted_versions,
            resolved_versions,
            vuln_id,
            identifier=None,
    ):
        vuln = None

        for version in impacted_versions:
            pkg = models.Package.objects.get(name=package_name, version=version)

            assert pkg.vulnerabilities.count() == 1
            vuln = pkg.vulnerabilities.first()
            if identifier:
                assert vuln.identifier == identifier

            ref_url = f'https://registry.npmjs.org/-/npm/v1/advisories/{vuln_id}'
            assert models.VulnerabilityReference.objects.get(url=ref_url, vulnerability=vuln)

        for version in resolved_versions:
            pkg = models.Package.objects.get(name=package_name, version=version)
            assert models.PackageRelatedVulnerability.objects.filter(
                package=pkg, vulnerability=vuln, is_vulnerable=False)


def test_categorize_versions_simple_ranges():
    all_versions = {'3.4', '3.8'}
    impacted_ranges = '<3.5.0'
    resolved_ranges = '>=3.5.0'

    impacted_versions, resolved_versions = categorize_versions(
        all_versions, impacted_ranges, resolved_ranges)

    assert impacted_versions == {'3.4'}
    assert resolved_versions == {'3.8'}


def test_categorize_versions_complex_ranges():
    all_versions = {'3.7', '4.1.1', '6.1.3', '7.0.0', '7.0.5'}
    impacted_ranges = '>=4.1.0 <6.1.3 || >= 7.0.0 <7.0.3'
    resolved_ranges = '>=6.1.3 <7.0.0 || >=7.0.3'

    impacted_versions, resolved_versions = categorize_versions(
        all_versions, impacted_ranges, resolved_ranges)

    assert impacted_versions == {'4.1.1', '7.0.0'}
    assert resolved_versions == {'3.7', '6.1.3', '7.0.5'}
