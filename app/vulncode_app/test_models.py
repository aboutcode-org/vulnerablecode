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
        summary_get = Vulnerability.objects.get(pk=summary_create.pk)

        self.assertEqual(str(summary_create), "Affected package xyz")


class TestVulnerabilityReference(TestCase):
    def test_vulnerability_reference(self):
        ref_id_create = VulnerabilityReference.objects.create(reference_id="CVE-2017-8564")
        ref_id_get = VulnerabilityReference.objects.get(pk=ref_id_create.pk)

        self.assertEqual(str(ref_id_create), "CVE-2017-8564")


class TestPackage(TestCase):
    def test_package(self):
        package_name_create = Package.objects.create(name="Firefox")
        package_name_get = Package.objects.get(pk=package_name_create.pk)

        self.assertEqual(str(package_name_create), "Firefox")


class TestPackageReference(TestCase):
    def test_package_reference(self):
        platform_create = PackageReference.objects.create(platform="Maven")
        platform_get = PackageReference.objects.get(pk=platform_create.pk)

        self.assertEqual(str(platform_create), "Maven")
