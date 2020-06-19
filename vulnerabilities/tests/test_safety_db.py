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
from vulnerabilities.importers.safety_db import PypiVersionAPI
from vulnerabilities.importers.safety_db import categorize_versions

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, 'test_data/')

MOCK_VERSION_API = PypiVersionAPI(cache={
    'ampache': {'2.0', '5.2.1'},
    'django': {'1.8', '1.4.19', '1.4.22', '1.5.1', '1.6.9', '1.8.14'},
    'zulip': {'2.0', '2.1.1', '2.1.2', '2.1.3'},
})


@patch('vulnerabilities.importers.SafetyDbDataSource.versions', new=MOCK_VERSION_API)
class SafetyDbImportTest(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture_path = os.path.join(TEST_DATA, 'safety_db', 'insecure_full.json')
        with open(fixture_path) as f:
            cls.mock_response = json.load(f)

        cls.importer = models.Importer.objects.create(
            name='safetydb_unittests',
            license='CC-BY-NC 4.0',
            last_run=None,
            data_source='SafetyDbDataSource',
            data_source_cfg={
                'url': 'https://example.com',
            },
        )

    @classmethod
    def tearDownClass(cls) -> None:
        # Make sure no requests for unexpected package names have been made during the tests.
        assert len(MOCK_VERSION_API.cache) == 3, MOCK_VERSION_API.cache

    def test_import(self):
        runner = ImportRunner(self.importer, 5)

        with patch(
                'vulnerabilities.importers.SafetyDbDataSource._fetch',
                return_value=self.mock_response
        ):
            runner.run()

        assert models.Vulnerability.objects.count() == 9
        assert models.VulnerabilityReference.objects.count() == 9
        assert models.PackageRelatedVulnerability.objects.filter(
            is_vulnerable=False).count() == 18
        assert models.PackageRelatedVulnerability.objects.filter(
            is_vulnerable=True).count() == 18

        expected_package_count = sum([len(v) for v in MOCK_VERSION_API.cache.values()])
        assert models.Package.objects.count() == expected_package_count

        self.assert_by_vulnerability(
            'pyup.io-37863',
            'ampache',
            {'2.0'},
            {'5.2.1'},
            cve_ids={'CVE-2019-12385', 'CVE-2019-12386'},
        )

        self.assert_by_vulnerability(
            'pyup.io-25713',
            'django',
            {'1.8', '1.4.19', '1.5.1', '1.6.9'},
            {'1.8.14', '1.4.22'},
            cve_ids={'CVE-2015-2317'},
        )

        self.assert_by_vulnerability(
            'pyup.io-25721',
            'django',
            {'1.8.14'},
            {'1.8', '1.4.19', '1.5.1', '1.6.9', '1.4.22'},
            cve_ids={'CVE-2016-6186'},
        )

        self.assert_by_vulnerability(
            'pyup.io-38115',
            'zulip',
            {'2.0'},
            {'2.1.1', '2.1.2', '2.1.3'},
        )

        self.assert_by_vulnerability(
            'pyup.io-38114',
            'zulip',
            {'2.0', '2.1.1'},
            {'2.1.2', '2.1.3'},
            cve_ids={'CVE-2019-19775', 'CVE-2015-2104'},
        )

        self.assert_by_vulnerability(
            'pyup.io-38200',
            'zulip',
            {'2.0', '2.1.1', '2.1.2'},
            {'2.1.3'},
            cve_ids={'CVE-2020-9444', 'CVE-2020-10935'},
        )

    def assert_by_vulnerability(
            self,
            vuln_ref,
            pkg_name,
            impacted_versions,
            resolved_versions,
            cve_ids=None,
    ):
        impacted_pkgs = set(models.Package.objects.filter(
            name=pkg_name, version__in=impacted_versions))

        assert len(impacted_pkgs) == len(impacted_versions)

        resolved_pkgs = set(models.Package.objects.filter(
            name=pkg_name, version__in=resolved_versions))

        assert len(resolved_pkgs) == len(resolved_versions)

        vuln_count = 1 if cve_ids is None else len(cve_ids)

        vulns = {r.vulnerability for r in
                 models.VulnerabilityReference.objects.filter(reference_id=vuln_ref)}

        assert len(vulns) == vuln_count

        for vuln in vulns:
            assert {ip.package for ip in
                    models.PackageRelatedVulnerability.objects.filter(
                        vulnerability=vuln, is_vulnerable=True)
                    } == impacted_pkgs

            assert {rp.package for rp in
                    models.PackageRelatedVulnerability.objects.filter(
                        vulnerability=vuln, is_vulnerable=False)
                    } == resolved_pkgs

        if cve_ids:
            assert {v.cve_id for v in vulns} == cve_ids


def test_categorize_versions():
    all_versions = {'1.8', '1.4.19', '1.4.22', '1.5.1', '1.6.9', '1.8.14'}
    version_specs = [">=1.8,<1.8.3", "<1.4.20", ">=1.5,<1.6", ">=1.6,<1.6.11", ">=1.7,<1.7.7"]

    impacted_purls, resolved_purls = categorize_versions('django', all_versions, version_specs)

    assert len(impacted_purls) == 4
    assert len(resolved_purls) == 2

    impacted_versions = {p.version for p in impacted_purls}
    resolved_versions = {p.version for p in resolved_purls}

    assert impacted_versions == {'1.8', '1.4.19', '1.5.1', '1.6.9'}
    assert resolved_versions == {'1.4.22', '1.8.14'}
