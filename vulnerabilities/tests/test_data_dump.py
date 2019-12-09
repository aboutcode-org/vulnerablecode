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

from django.test import TestCase

from core.models import ImpactedPackage
from core.models import Package
from core.models import PackageReference
from core.models import ResolvedPackage
from core.models import Vulnerability
from core.models import VulnerabilityReference
from vulnerabilities.data_dump import archlinux_dump
from vulnerabilities.data_dump import debian_dump
from vulnerabilities.data_dump import ubuntu_dump
from vulnerabilities.scraper import archlinux
from vulnerabilities.scraper import debian
from vulnerabilities.scraper import ubuntu


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, 'test_data/')


class TestDebianDataDump(TestCase):
    @classmethod
    def setUpTestData(cls):
        with open(os.path.join(TEST_DATA, 'debian.json')) as f:
            test_data = json.load(f)

        extract_data = debian.extract_vulnerabilities(test_data)
        debian_dump(extract_data)

    def test_Vulnerability(self):
        """
        Check that all vulnerabilities from the test data are stored in the database
        """
        self.assertEqual(3, Vulnerability.objects.count())

        self.assertTrue(Vulnerability.objects.filter(cve_id='CVE-2009-1382'))
        self.assertTrue(Vulnerability.objects.filter(cve_id='CVE-2009-2459'))
        self.assertTrue(Vulnerability.objects.filter(cve_id='CVE-2014-8242'))

    def test_VulnerabilityReference(self):
        """
        Check that no vulnerability references were found in the test data
        """
        self.assertEqual(0, VulnerabilityReference.objects.count())

    def test_Package(self):
        """
        Check that all packages from the test data are stored in the database
        """
        # There are five rows in Package because currently the models allow duplicates
        # (see issue #28).
        self.assertEqual(5, Package.objects.count())

        self.assertTrue(Package.objects.filter(name='mimetex'))

        pkg = Package.objects.get(name='librsync')
        self.assertEqual('0.9.7-10', pkg.version)
        self.assertEqual('deb', pkg.type)
        self.assertEqual('debian', pkg.namespace)
        self.assertIn('distro=jessie', pkg.qualifiers)

    def test_ImpactedPackage(self):
        """
        Check that all impacted packages from the test data are stored in the database
        """
        impacted_pkgs = ImpactedPackage.objects.all()

        self.assertEqual(1, impacted_pkgs.count())

        ip = impacted_pkgs[0]
        self.assertEqual('librsync', ip.package.name)
        self.assertEqual('0.9.7-10', ip.package.version)

    def test_ResolvedPackage(self):
        """
        Check that all resolved packages from the test data are stored in the database
        """
        resolved_pkgs = ResolvedPackage.objects.all()
        versions = [rp.package.version for rp in resolved_pkgs]

        self.assertEqual(4, resolved_pkgs.count())
        self.assertEqual('mimetex', resolved_pkgs[0].package.name)
        self.assertIn('1.50-1.1', versions)
        self.assertIn('1.74-1', versions)


class TestUbuntuDataDump(TestCase):
    @classmethod
    def setUpTestData(cls):
        with open(os.path.join(TEST_DATA, 'ubuntu_main.html')) as f:
            test_data = f.read()

        data = ubuntu.extract_cves(test_data)
        ubuntu_dump(data)

    def test_data_dump(self):
        """
        Check basic data import
        """
        self.assertTrue(Vulnerability.objects.filter(cve_id='CVE-2002-2439'))
        pkgs = Package.objects.filter(name='gcc-4.6')
        self.assertTrue(pkgs)

        pkg = pkgs[0]
        self.assertEqual('deb', pkg.type)
        self.assertEqual('ubuntu', pkg.namespace)


class TestArchLinuxDataDump(TestCase):

    CVE_IDS = ('CVE-2018-11362', 'CVE-2018-11361', 'CVE-2018-11360',
               'CVE-2018-11359', 'CVE-2018-11358', 'CVE-2018-11357',
               'CVE-2018-11356', 'CVE-2018-11355', 'CVE-2018-11354')

    @classmethod
    def setUpTestData(cls):
        with open(os.path.join(TEST_DATA, 'archlinux.json')) as f:
            test_data = json.load(f)

        archlinux_dump(test_data)

    def test_Vulnerability(self):
        """
        Check that all vulnerabilities from the test data are stored in the database
        """
        self.assertEqual(len(self.CVE_IDS), Vulnerability.objects.count())

        for cve_id in self.CVE_IDS:
            self.assertTrue(Vulnerability.objects.filter(cve_id=cve_id))

    def test_VulnerabilityReference(self):
        """
        Check that all vulnerability references from the test data are stored in the database
        """
        for ref in ('ASA-201805-22', 'ASA-201805-23', 'ASA-201805-24', 'ASA-201805-25', 'AVG-708'):
            self.assertEqual(
                    len(self.CVE_IDS),
                    VulnerabilityReference.objects.filter(reference_id=ref).count()
            )

        for ref in self.CVE_IDS:
            url = f'https://security.archlinux.org/{ref}'
            self.assertEqual(1, VulnerabilityReference.objects.filter(url=url).count())

    def test_Package(self):
        """
        Check that all packages from the test data are stored in the database
        """
        self.assertEqual(8, Package.objects.count())

        for pkg in ('wireshark-common', 'wireshark-gtk', 'wireshark-cli', 'wireshark-qt'):
            for ver in ('2.6.0-1', '2.6.1-1'):
                self.assertTrue(Package.objects.filter(name=pkg, version=ver))

        for pkg in Package.objects.filter(name='wireshark-cli'):
            self.assertEqual('pacman', pkg.type)
            self.assertEqual('archlinux', pkg.namespace)

    def test_PackageReference(self):
        """
        Check that no package references were found in the test data
        """
        self.assertEqual(0, PackageReference.objects.count())

    def test_ImpactedPackage(self):
        """
        Check there is one ImpactedPackage for the number of packages
        with the affected version number, times the number of vulnerabilities
        """
        packages = Package.objects.filter(version='2.6.0-1')
        vulnerabilities = Vulnerability.objects.all()

        impacted_pkgs_count = ImpactedPackage.objects.count()
        expected_count = packages.count() * vulnerabilities.count()

        self.assertEqual(expected_count, impacted_pkgs_count)

        for pkg in packages:
            for vuln in vulnerabilities:
                self.assertTrue(ImpactedPackage.objects.filter(
                    package=pkg,
                    vulnerability=vuln,
                ))

    def test_ResolvedPackage(self):
        """
        Check there is one ResolvedPackage for the number of packages
        with the fixed version number, times the number of vulnerabilities
        """
        packages = Package.objects.filter(version='2.6.1-1')
        vulnerabilities = Vulnerability.objects.all()

        resolved_pkgs_count = ResolvedPackage.objects.count()
        expected_count = packages.count() * vulnerabilities.count()

        self.assertEqual(expected_count, resolved_pkgs_count)

        for pkg in packages:
            for vuln in vulnerabilities:
                self.assertTrue(ResolvedPackage.objects.filter(
                    package=pkg,
                    vulnerability=vuln,
                ))
