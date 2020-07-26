#
# Copyright (c) nexB Inc. and others. All rights reserved.
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
import dataclasses
from copy import deepcopy
from datetime import datetime

from vulnerabilities import models
from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import PackageURL
from vulnerabilities.data_source import Reference
from vulnerabilities.import_runner import ImportRunner
from vulnerabilities.import_runner import _insert_vulnerabilities_and_references


class MockDataSource(DataSource):

    def __init__(self, *args, **kwargs):
        self.added_advs = kwargs.pop('added_advs', [])
        self.updated_advs = kwargs.pop('updated_advs', [])
        super().__init__(*args, **kwargs)

    def added_advisories(self):
        return self._yield_advisories(self.added_advs[:])

    def updated_advisories(self):
        return self._yield_advisories(self.updated_advs[:])

    def _yield_advisories(self, advisories):
        while advisories:
            b, advisories = advisories[:self.batch_size], advisories[self.batch_size:]
            yield b


@dataclasses.dataclass
class MockImporter:
    data_source: MockDataSource
    last_run: datetime = None
    name: str = 'mock_importer'
    license: str = 'license to test'
    saved: bool = False

    def make_data_source(self, *_, **__):
        return self.data_source

    def save(self):
        self.saved = True


ADVISORIES = [
    Advisory(
        cve_id='MOCK-CVE-2020-1337',
        summary='vulnerability description here',
        vuln_references=[
            Reference(
                url='https://example.com/with/more/info/MOCK-CVE-2020-1337')],
        impacted_package_urls=[
            PackageURL(
                name='mock-webserver',
                type='pypi',
                version='1.2.33')],
        resolved_package_urls=[
            PackageURL(
                name='mock-webserver',
                type='pypi',
                version='1.2.34')],
    )]


def make_import_runner(added_advs=None, updated_advs=None):
    added_advs = added_advs or []
    updated_advs = updated_advs or []

    importer = MockImporter(
        data_source=MockDataSource(2, added_advs=added_advs, updated_advs=updated_advs))

    return ImportRunner(importer, 5)


def test_ImportRunner_new_package_and_new_vulnerability(db):
    runner = make_import_runner(added_advs=ADVISORIES)

    runner.run()

    assert runner.importer.last_run is not None
    assert runner.importer.saved

    assert models.Package.objects.all().count() == 2
    packages = models.Package.objects.filter(name='mock-webserver')

    if packages[0].version == '1.2.33':
        impacted_package, resolved_package = packages[0], packages[1]
    else:
        impacted_package, resolved_package = packages[1], packages[0]

    assert models.Vulnerability.objects.count() == 1
    assert models.VulnerabilityReference.objects.count() == 1
    assert models.PackageRelatedVulnerability.objects.count() == 2

    assert impacted_package.vulnerabilities.count() == 1
    assert resolved_package.vulnerabilities.count() == 1

    vuln = impacted_package.vulnerabilities.first()
    assert vuln.cve_id == 'MOCK-CVE-2020-1337'

    vuln_refs = models.VulnerabilityReference.objects.filter(vulnerability=vuln)
    assert vuln_refs.count() == 1
    assert vuln_refs[0].url == 'https://example.com/with/more/info/MOCK-CVE-2020-1337'


def test_ImportRunner_existing_package_and_new_vulnerability(db):
    """
    Both versions of the package mentioned in the imported advisory are already in the database.
    Only the vulnerability itself is new.
    """
    models.Package.objects.create(name='mock-webserver', type='pypi', version='1.2.33')
    models.Package.objects.create(name='mock-webserver', type='pypi', version='1.2.34')

    runner = make_import_runner(added_advs=ADVISORIES)

    runner.run()

    assert runner.importer.last_run is not None
    assert runner.importer.saved

    assert models.Vulnerability.objects.count() == 1
    assert models.VulnerabilityReference.objects.count() == 1

    assert models.PackageRelatedVulnerability.objects.count() == 2

    resolved_package = models.PackageRelatedVulnerability.objects.filter(is_vulnerable=False)[0]
    assert resolved_package.package.version == '1.2.34'

    impacted_package = models.PackageRelatedVulnerability.objects.filter(is_vulnerable=True)[0]
    vuln = impacted_package.vulnerability
    assert vuln.cve_id == 'MOCK-CVE-2020-1337'

    vuln_refs = models.VulnerabilityReference.objects.filter(vulnerability=vuln)
    assert vuln_refs.count() == 1
    assert vuln_refs[0].url == 'https://example.com/with/more/info/MOCK-CVE-2020-1337'


def test_ImportRunner_new_package_version_affected_by_existing_vulnerability(db):
    """
    Another version of a package existing in the database is added to the impacted packages of a
    vulnerability that also already existed in the database.
    """
    vuln = models.Vulnerability.objects.create(
        cve_id='MOCK-CVE-2020-1337', summary='vulnerability description here')

    models.VulnerabilityReference.objects.create(
        vulnerability=vuln,
        url='https://example.com/with/more/info/MOCK-CVE-2020-1337'
    )
    models.PackageRelatedVulnerability.objects.create(
        vulnerability=vuln,
        package=models.Package.objects.create(name='mock-webserver', type='pypi', version='1.2.33'),
        is_vulnerable=True
    )
    models.PackageRelatedVulnerability.objects.create(
        vulnerability=vuln,
        package=models.Package.objects.create(name='mock-webserver', type='pypi', version='1.2.34'),
        is_vulnerable=False
    )

    advisories = deepcopy(ADVISORIES)
    advisories[0].impacted_package_urls.append(
        PackageURL(name='mock-webserver', type='pypi', version='1.2.33a'))
    runner = make_import_runner(updated_advs=advisories)

    runner.run()

    assert runner.importer.last_run is not None
    assert runner.importer.saved

    assert models.Package.objects.all().count() == 3
    assert models.Vulnerability.objects.count() == 1
    assert models.VulnerabilityReference.objects.count() == 1
    assert models.PackageRelatedVulnerability.objects.count() == 3

    qs = models.Package.objects.filter(name='mock-webserver', version='1.2.33a')
    assert len(qs) == 1
    added_package = qs[0]

    qs = models.PackageRelatedVulnerability.objects.filter(
        package=added_package, is_vulnerable=True)
    assert len(qs) == 1
    impacted_package = qs[0]
    assert impacted_package.vulnerability.cve_id == 'MOCK-CVE-2020-1337'


# def test_ImportRunner_assumed_fixed_package_is_updated_as_impacted(db):
#     """
#     A version of a package existing in the database that was assumed to be fixed was found to
#     still be affected by a vulnerability that also already existed in the database (i.e. the
#     previously stored data was corrected).
#     """
    # FIXME This case is not supported due to cascading deletes. When the ResolvedPackage is
    # FIXME deleted, the referenced Package and Vulnerability are also deleted.
    #
    # vuln = models.Vulnerability.objects.create(
    #     cve_id='MOCK-CVE-2020-1337', summary='vulnerability description here')
    #
    # models.VulnerabilityReference.objects.create(
    #     vulnerability=vuln,
    #     url='https://example.com/with/more/info/MOCK-CVE-2020-1337'
    # )
    #
    # misclassified_package = models.Package.objects.create(
    #     name='mock-webserver', type='pypi', version='1.2.33')
    #
    # models.ResolvedPackage.objects.create(
    #     vulnerability=vuln,
    #     package=misclassified_package,
    # )
    # models.ResolvedPackage.objects.create(
    #     vulnerability=vuln,
    #     package=models.Package.objects.create(
    #         name='mock-webserver', type='pypi', version='1.2.34'),
    # )
    #
    # runner = make_import_runner(updated_advs=ADVISORIES)
    #
    # runner.run()
    #
    # assert runner.importer.last_run is not None
    # assert runner.importer.saved
    #
    # assert models.Package.objects.all().count() == 2
    # assert models.Vulnerability.objects.count() == 1
    # assert models.VulnerabilityReference.objects.count() == 1
    # assert models.ImpactedPackage.objects.count() == 2
    # assert models.ResolvedPackage.objects.count() == 0
    #
    # assert models.ImpactedPackage.objects.filter(package=misclassified_package).count() == 1
    # assert models.ResolvedPackage.objects.filter(package=misclassified_package).count() == 0


def test_ImportRunner_fixed_package_version_is_added(db):
    """
    A new version of a package was published that fixes a previously unresolved vulnerability.
    """
    vuln = models.Vulnerability.objects.create(
        cve_id='MOCK-CVE-2020-1337', summary='vulnerability description here')

    models.VulnerabilityReference.objects.create(
        vulnerability=vuln,
        url='https://example.com/with/more/info/MOCK-CVE-2020-1337'
    )
    models.PackageRelatedVulnerability.objects.create(
        vulnerability=vuln,
        package=models.Package.objects.create(name='mock-webserver', type='pypi', version='1.2.33'),
        is_vulnerable=True,
    )

    runner = make_import_runner(updated_advs=ADVISORIES)

    runner.run()

    assert runner.importer.last_run is not None
    assert runner.importer.saved

    assert models.Package.objects.all().count() == 2
    assert models.Vulnerability.objects.count() == 1
    assert models.VulnerabilityReference.objects.count() == 1
    assert models.PackageRelatedVulnerability.objects.count() == 2

    qs = models.Package.objects.filter(name='mock-webserver', version='1.2.34')
    assert len(qs) == 1
    added_package = qs[0]

    qs = models.PackageRelatedVulnerability.objects.filter(
        package=added_package, is_vulnerable=False)
    assert len(qs) == 1
    resolved_package = qs[0]
    assert resolved_package.vulnerability.cve_id == 'MOCK-CVE-2020-1337'


def test_ImportRunner_updated_vulnerability(db):
    """
    An existing vulnerability is updated with more information; a more detailed summary and a new
    reference.
    """
    vuln = models.Vulnerability.objects.create(
        cve_id='MOCK-CVE-2020-1337', summary='temporary description')

    models.PackageRelatedVulnerability.objects.create(
        vulnerability=vuln,
        package=models.Package.objects.create(name='mock-webserver', type='pypi', version='1.2.33'),
        is_vulnerable=True
    )
    models.PackageRelatedVulnerability.objects.create(
        vulnerability=vuln,
        package=models.Package.objects.create(name='mock-webserver', type='pypi', version='1.2.34'),
        is_vulnerable=False
    )

    runner = make_import_runner(updated_advs=ADVISORIES)

    runner.run()

    assert runner.importer.last_run is not None
    assert runner.importer.saved

    assert models.Package.objects.all().count() == 2
    assert models.PackageRelatedVulnerability.objects.count() == 2

    vuln = models.Vulnerability.objects.first()
    assert vuln.summary == 'vulnerability description here'

    vuln_refs = models.VulnerabilityReference.objects.filter(vulnerability=vuln)
    assert vuln_refs.count() == 1
    assert vuln_refs[0].url == 'https://example.com/with/more/info/MOCK-CVE-2020-1337'


def test_insert_vulnerabilities_and_references_stores_summary(db):
    advisory = Advisory(
        summary='vulnerability description here',
        cve_id='MOCK-CVE-2020-1337',
        impacted_package_urls=[PackageURL(name='mock-webserver', type='pypi', version='1.2.33a')],
    )

    _insert_vulnerabilities_and_references({advisory})

    vuln = models.Vulnerability.objects.get(cve_id=advisory.cve_id)
    assert vuln.summary == advisory.summary
