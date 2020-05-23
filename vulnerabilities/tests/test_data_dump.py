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
