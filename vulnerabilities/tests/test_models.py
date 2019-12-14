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

import pytest

from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import Package
from vulnerabilities.models import PackageReference


def test_vulnerability(db):
    Vulnerability.objects.create(
        summary="Affected package xyz",
        cvss="7.8"
    )

    assert Vulnerability.objects.get(summary="Affected package xyz")
    assert Vulnerability.objects.get(cvss="7.8")


def test_vulnerability_reference(db):
    VulnerabilityReference.objects.create(
        vulnerability=Vulnerability.objects.create(summary="XYZ"),
        reference_id="CVE-2017-8564",
        source="NVD",
        url="http://mitre.com"
    )

    assert VulnerabilityReference.objects.get(reference_id="CVE-2017-8564")
    assert VulnerabilityReference.objects.get(source="NVD")
    assert VulnerabilityReference.objects.get(url="http://mitre.com")


def test_package(db):
    Package.objects.create(
        name="Firefox",
        version="1.5.4"
    )

    assert Package.objects.get(name="Firefox")
    assert Package.objects.get(version="1.5.4")


def test_package_reference(db):
    PackageReference.objects.create(
        package=Package.objects.create(name="Iceweasel"),
        platform="Maven",
        repository="http://central.maven.org",
        name="org.apache.commons.io",
        version="7.6.5"
    )

    assert PackageReference.objects.get(platform="Maven")
    assert PackageReference.objects.get(repository="http://central.maven.org")
    assert PackageReference.objects.get(name="org.apache.commons.io")
    assert PackageReference.objects.get(version="7.6.5")
