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
        summary_create = Vulnerability.objects.create(
                                                summary="Affected package xyz",
                                                cvss="7.8"
                                            )

        self.assertTrue(Vulnerability.objects.get(summary="Affected package xyz"))
        self.assertTrue(Vulnerability.objects.get(cvss="7.8"))


class TestVulnerabilityReference(TestCase):
    def test_vulnerability_reference(self):
        data_create = VulnerabilityReference.objects.create(
                                        vulnerability=Vulnerability.objects.create(summary="XYZ"),
                                        reference_id="CVE-2017-8564",
                                        source="NVD",
                                        url="http://mitre.com"
                                    )

        self.assertTrue(VulnerabilityReference.objects.get(reference_id="CVE-2017-8564"))
        self.assertTrue(VulnerabilityReference.objects.get(source="NVD"))
        self.assertTrue(VulnerabilityReference.objects.get(url="http://mitre.com"))


class TestPackage(TestCase):
    def test_package(self):
        data_create = Package.objects.create(
                                        name="Firefox",
                                        platform="Maven",
                                        version="1.5.4"
                                    )

        self.assertTrue(Package.objects.get(name="Firefox"))
        self.assertTrue(Package.objects.get(platform="Maven"))
        self.assertTrue(Package.objects.get(version="1.5.4"))


class TestPackageReference(TestCase):
    def test_package_reference(self):
        data_create = PackageReference.objects.create(
                                            package=Package.objects.create(name="Iceweasel"),
                                            platform="Maven",
                                            repository="http://central.maven.org",
                                            name="org.apache.commons.io",
                                            version="7.6.5"
                                        )

        self.assertTrue(PackageReference.objects.get(platform="Maven"))
        self.assertTrue(PackageReference.objects.get(repository="http://central.maven.org"))
        self.assertTrue(PackageReference.objects.get(name="org.apache.commons.io"))
        self.assertTrue(PackageReference.objects.get(version="7.6.5"))
