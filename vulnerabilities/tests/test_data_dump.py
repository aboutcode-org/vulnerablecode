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
import pytest

from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import Package
from vulnerabilities.models import ResolvedPackage
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, 'test_data/')


def test_debian_Vulnerability(setDebianData):
    """
    Check that all vulnerabilities from the test data are stored in the database
    """
    assert 3 == Vulnerability.objects.count()

    assert Vulnerability.objects.filter(cve_id='CVE-2009-1382')
    assert Vulnerability.objects.filter(cve_id='CVE-2009-2459')
    assert Vulnerability.objects.filter(cve_id='CVE-2014-8242')


def test_debian_VulnerabilityReference(setDebianData):
    """
    Check that no vulnerability references were found in the test data
    """
    assert 0 == VulnerabilityReference.objects.count()


def test_debian_Package(setDebianData):
    """
    Check that all packages from the test data are stored in the database
    """
    # There are five rows in Package because currently the models allow duplicates
    # (see issue #28).
    assert 5 == Package.objects.count()

    assert Package.objects.filter(name='mimetex')

    pkg = Package.objects.get(name='librsync')
    assert '0.9.7-10' == pkg.version
    assert 'deb' == pkg.type
    assert 'debian' == pkg.namespace
    assert 'distro=jessie' in pkg.qualifiers


def test_debian_ImpactedPackage(setDebianData):
    """
    Check that all impacted packages from the test data are stored in the database
    """
    impacted_pkgs = ImpactedPackage.objects.all()

    assert 1 == impacted_pkgs.count()

    ip = impacted_pkgs[0]
    assert 'librsync' == ip.package.name
    assert '0.9.7-10' == ip.package.version


def test_debian_ResolvedPackage(setDebianData):
    """
    Check that all resolved packages from the test data are stored in the database
    """
    resolved_pkgs = ResolvedPackage.objects.all()
    versions = [rp.package.version for rp in resolved_pkgs]

    assert 4 == resolved_pkgs.count()
    assert 'mimetex' == resolved_pkgs[0].package.name
    assert '1.50-1.1' in versions
    assert '1.74-1' in versions


def test_ubuntu_data_dump(setUbuntuData):
    """
    Check basic data import
    """
    assert Vulnerability.objects.filter(cve_id='CVE-2002-2439')
    pkgs = Package.objects.filter(name='gcc-4.6')
    assert pkgs

    pkg = pkgs[0]
    assert 'deb' == pkg.type
    assert 'ubuntu' == pkg.namespace


CVE_IDS = ('CVE-2018-11362', 'CVE-2018-11361', 'CVE-2018-11360',
           'CVE-2018-11359', 'CVE-2018-11358', 'CVE-2018-11357',
           'CVE-2018-11356', 'CVE-2018-11355', 'CVE-2018-11354')


def test_arch_Vulnerability(setArchLinuxData):
    """
    Check that all vulnerabilities from the test data are stored in the database
    """
    assert len(CVE_IDS) == Vulnerability.objects.count()

    for cve_id in CVE_IDS:
        assert Vulnerability.objects.filter(cve_id=cve_id)


def test_arch_VulnerabilityReference(setArchLinuxData):
    """
    Check that all vulnerability references from the test data are stored in the database
    """
    for ref in ('ASA-201805-22', 'ASA-201805-23', 'ASA-201805-24', 'ASA-201805-25', 'AVG-708'):
        assert len(CVE_IDS) == VulnerabilityReference.objects.filter(
            reference_id=ref).count()

    for ref in CVE_IDS:
        url = f'https://security.archlinux.org/{ref}'
        assert 1 == VulnerabilityReference.objects.filter(url=url).count()


def test_arch_Package(setArchLinuxData):
    """
    Check that all packages from the test data are stored in the database
    """
    assert 8 == Package.objects.count()

    for pkg in ('wireshark-common', 'wireshark-gtk', 'wireshark-cli', 'wireshark-qt'):
        for ver in ('2.6.0-1', '2.6.1-1'):
            assert Package.objects.filter(name=pkg, version=ver)

    for pkg in Package.objects.filter(name='wireshark-cli'):
        assert 'pacman' == pkg.type
        assert 'archlinux' == pkg.namespace


def test_arch_ImpactedPackage(setArchLinuxData):
    """
    Check there is one ImpactedPackage for the number of packages
    with the affected version number, times the number of vulnerabilities
    """
    packages = Package.objects.filter(version='2.6.0-1')
    vulnerabilities = Vulnerability.objects.all()

    impacted_pkgs_count = ImpactedPackage.objects.count()
    expected_count = packages.count() * vulnerabilities.count()

    assert expected_count == impacted_pkgs_count

    for pkg in packages:
        for vuln in vulnerabilities:
            assert ImpactedPackage.objects.filter(
                package=pkg,
                vulnerability=vuln,
            )


def test_arch_ResolvedPackage(setArchLinuxData):
    """
    Check there is one ResolvedPackage for the number of packages
    with the fixed version number, times the number of vulnerabilities
    """
    packages = Package.objects.filter(version='2.6.1-1')
    vulnerabilities = Vulnerability.objects.all()

    resolved_pkgs_count = ResolvedPackage.objects.count()
    expected_count = packages.count() * vulnerabilities.count()

    assert expected_count == resolved_pkgs_count

    for pkg in packages:
        for vuln in vulnerabilities:
            assert ResolvedPackage.objects.filter(
                package=pkg,
                vulnerability=vuln,
            )
