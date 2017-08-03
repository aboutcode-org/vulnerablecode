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

from django.test import TestCase

from vulncode_app.models import Vulnerability
from vulncode_app.models import VulnerabilityReference
from vulncode_app.models import ImpactedPackage
from vulncode_app.models import ResolvedPackage
from vulncode_app.models import Package
from vulncode_app.models import PackageReference


class TestVulnerability(TestCase):
    def test_vulnerability(self):
        summary_create = Vulnerability.objects.create(summary="Affected package xyz")
        summary_get = Vulnerability.objects.get(pk=1)

        cvss_create = Vulnerability.objects.create(cvss="7.8")
        cvss_get = Vulnerability.objects.get(pk=2)

        self.assertEqual("Affected package xyz", summary_get.summary)
        self.assertEqual(7.8, cvss_get.cvss)


class TestVulnerabilityReference(TestCase):
    def test_vulnerability_reference(self):
        reference_id_create = VulnerabilityReference.objects.create(reference_id="CVE-2017-8564")
        reference_id_get = VulnerabilityReference.objects.get(pk=1)

        source_create = VulnerabilityReference.objects.create(source="NVD")
        source_get = VulnerabilityReference.objects.get(pk=2)

        url_create = VulnerabilityReference.objects.create(url="http://mitre.com")
        url_get = VulnerabilityReference.objects.get(pk=3)

        self.assertEqual(reference_id_get.reference_id, "CVE-2017-8564")
        self.assertEqual(source_get.source, "NVD")
        self.assertEqual(url_get.url, "http://mitre.com")


class TestPackage(TestCase):
    def test_package(self):
        name_create = Package.objects.create(name="Firefox")
        name_get = Package.objects.get(pk=1)

        platform_create = Package.objects.create(platform="Maven")
        platform_get = Package.objects.get(pk=2)

        version_create = Package.objects.create(version="1.5.4")
        version_get = Package.objects.get(pk=3)

        self.assertEqual(name_get.name, "Firefox")
        self.assertEqual(platform_get.platform, "Maven")
        self.assertEqual(version_get.version, "1.5.4")


class TestPackageReference(TestCase):
    def test_package_reference(self):
        platform_create = PackageReference.objects.create(platform="Maven")
        platform_get = PackageReference.objects.get(pk=1)

        repository_create = PackageReference.objects.create(repository="http://central.maven.org")
        repository_get = PackageReference.objects.get(pk=2)

        name_create = PackageReference.objects.create(name="org.apache.commons.io")
        name_get = PackageReference.objects.get(pk=3)

        version_create = PackageReference.objects.create(version="7.6.5")
        version_get = PackageReference.objects.get(pk=4)

        self.assertEqual(platform_get.platform, "Maven")
        self.assertEqual(repository_get.repository, "http://central.maven.org")
        self.assertEqual(name_get.name, "org.apache.commons.io")
        self.assertEqual(version_get.version, "7.6.5")
