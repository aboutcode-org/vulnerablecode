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

from vulnerabilities.data_dump import archlinux_dump
from vulnerabilities.data_dump import debian_dump
from vulnerabilities.data_dump import ubuntu_dump
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import Package
from vulnerabilities.models import PackageReference
from vulnerabilities.models import ResolvedPackage
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.scraper import archlinux
from vulnerabilities.scraper import debian
from vulnerabilities.scraper import ubuntu


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, 'test_data/')


class TestDebianDataDump(TestCase):

    @classmethod
    def setUpTestData(self):
        with open(os.path.join(TEST_DATA, 'debian.json')) as f:
            test_data = json.load(f)

        extract_data = debian.extract_vulnerabilities(test_data)
        debian_dump(extract_data)

    def test_Vulnerability(self):
        """
        Check that all vulnerabilities from the test data are stored in the database
        """
        self.assertEqual(3, Vulnerability.objects.count())

        self.assertTrue(Vulnerability.objects.get(
                        summary='Multiple stack-based buffer overflows in mimetex.cgi in mimeTeX'))

        self.assertTrue(Vulnerability.objects.get(
                        summary='Multiple unspecified vulnerabilities in mimeTeX'))

        self.assertTrue(Vulnerability.objects.get(
                        summary='librsync before 1.0.0 uses a truncated MD4 checksum \
to match blocks'))

    def test_VulnerabilityReference(self):
        """
        Check that all vulnerability references from the test data are stored in the database
        """
        self.assertEqual(3, VulnerabilityReference.objects.count())
        self.assertTrue(VulnerabilityReference.objects.get(reference_id='CVE-2009-1382'))
        self.assertTrue(VulnerabilityReference.objects.get(reference_id='CVE-2009-2459'))
        self.assertTrue(VulnerabilityReference.objects.get(reference_id='CVE-2014-8242'))

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
        impacted_pkg = impacted_pkgs[0]

        self.assertEqual(1, len(impacted_pkgs))
        self.assertEqual('librsync', impacted_pkg.package.name)
        self.assertEqual('0.9.7-10', impacted_pkg.package.version)

    def test_ResolvedPackage(self):
        """
        Check that all resolved packages from the test data are stored in the database
        """
        resolved_pkgs = ResolvedPackage.objects.all()
        resolved_pkg = resolved_pkgs[0]
        versions = [rp.package.version for rp in resolved_pkgs]

        self.assertEqual(4, len(resolved_pkgs))
        self.assertEqual('mimetex', resolved_pkg.package.name)
        self.assertIn('1.50-1.1', versions)
        self.assertIn('1.74-1', versions)


class TestUbuntuDataDump(TestCase):
    @classmethod
    def setUpTestData(self):
        with open(os.path.join(TEST_DATA, 'ubuntu_main.html')) as f:
            test_data = f.read()

        data = ubuntu.extract_cves(test_data)
        ubuntu_dump(data)

    def test_data_dump(self):
        """
        Check basic data import
        """
        reference = VulnerabilityReference.objects.filter(reference_id='CVE-2002-2439')[0]
        self.assertEqual(reference.reference_id, 'CVE-2002-2439')
        pkgs = Package.objects.filter(name='gcc-4.6')
        self.assertTrue(pkgs)

        pkg = pkgs[0]
        self.assertEqual('deb', pkg.type)
        self.assertEqual('ubuntu', pkg.namespace)


class TestArchLinuxDataDump(TestCase):

    @classmethod
    def setUpTestData(self):
        with open(os.path.join(TEST_DATA, 'archlinux.json')) as f:
            test_data = json.load(f)

        archlinux_dump(test_data)

    def test_Vulnerability(self):
        """
        Check that all vulnerabilities from the test data are stored in the database
        """
        self.assertEqual(1, Vulnerability.objects.count())
        self.assertTrue(Vulnerability.objects.get(summary='multiple issues'))

    def test_VulnerabilityReference(self):
        """
        Check that all vulnerability references from the test data are stored in the database
        """
        self.assertEqual(14, VulnerabilityReference.objects.count())
        self.assertTrue(VulnerabilityReference.objects.get(reference_id='CVE-2018-11360'))
        self.assertTrue(VulnerabilityReference.objects.get(reference_id='ASA-201805-24'))
        self.assertTrue(VulnerabilityReference.objects.get(reference_id='AVG-708'))

    def test_Package(self):
        """
        Check that all packages from the test data are stored in the database
        """
        self.assertEqual(8, Package.objects.count())
        pkgs = Package.objects.filter(name='wireshark-cli')
        self.assertTrue(pkgs)

        for pkg in pkgs:
            self.assertEqual('pacman', pkg.type)
            self.assertEqual('archlinux', pkg.namespace)

    def test_PackageReference(self):
        """
        Check that all package references from the test data are stored in the database
        """
        self.assertEqual(8, PackageReference.objects.count())

    def test_ImpactedPackage(self):
        """
        Check that all impacted packages from the test data are stored in the database
        """
        impacted_pkgs = ImpactedPackage.objects.all()
        impacted_pkg = impacted_pkgs[0]

        self.assertEqual(4, len(impacted_pkgs))
        self.assertEqual('2.6.0-1', impacted_pkg.package.version)

    def test_ResolvedPackage(self):
        """
        Check that all resolved packages from the test data are stored in the database
        """
        resolved_pkgs = ResolvedPackage.objects.all()
        resolved_pkg = resolved_pkgs[0]

        self.assertEqual(4, len(resolved_pkgs))
        self.assertEqual('2.6.1-1', resolved_pkg.package.version)
