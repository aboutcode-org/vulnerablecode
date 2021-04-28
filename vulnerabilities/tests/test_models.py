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
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

from datetime import datetime
from unittest import TestCase

import pytest
from freezegun import freeze_time

from vulnerabilities import models


class TestVulnerabilityModel(TestCase):
    def test_generate_vulcoid_given_timestamp_object(self):
        timestamp_object = datetime(2021, 1, 1, 11, 12, 13, 2000)
        expected_vulcoid = "VULCOID-20210101-1112-13002000"
        found_vulcoid = models.Vulnerability.generate_vulcoid(timestamp_object)
        assert expected_vulcoid == found_vulcoid

    def test_generate_vulcoid(self):
        expected_vulcoid = "VULCOID-20210101-1112-13000000"
        with freeze_time("2021-01-01 11:12:13.000000"):
            found_vulcoid = models.Vulnerability.generate_vulcoid()
        assert expected_vulcoid == found_vulcoid

    @pytest.mark.django_db
    def test_vulnerability_save_with_vulnerability_id(self):
        models.Vulnerability(vulnerability_id="CVE-2020-7965").save()
        assert models.Vulnerability.objects.filter(vulnerability_id="CVE-2020-7965").count() == 1

    @pytest.mark.django_db
    def test_vulnerability_save_without_vulnerability_id(self):
        assert (
            models.Vulnerability.objects.filter(
                vulnerability_id="VULCOID-20210101-1112-13000000"
            ).count()
            == 0
        )

        with freeze_time("2021-01-01 11:12:13.000000"):
            models.Vulnerability(vulnerability_id="").save()
            assert (
                models.Vulnerability.objects.filter(
                    vulnerability_id="VULCOID-20210101-1112-13000000"
                ).count()
                == 1
            )


# FIXME: The fixture code is duplicated. setUpClass is not working with the pytest mark.
@pytest.mark.django_db
class TestPackageRelatedVulnerablity(TestCase):
    def test_package_to_vulnerability(self):
        p1 = models.Package.objects.create(type="deb", name="git", version="2.30.1")
        p2 = models.Package.objects.create(type="deb", name="git", version="2.31.1")
        v1 = models.Vulnerability.objects.create(vulnerability_id="CVE-123-2002")

        prv1 = models.PackageRelatedVulnerability.objects.create(
            patched_package=p2, package=p1, vulnerability=v1
        )

        assert p1.vulnerabilities.all().count() == 1
        assert p1.resolved_vulnerabilities.all().count() == 0
        assert p1.vulnerabilities.all()[0] == v1

        assert p2.vulnerabilities.all().count() == 0
        assert p2.resolved_vulnerabilities.all().count() == 1
        assert p2.resolved_vulnerabilities.all()[0] == v1

    def test_vulnerability_package(self):
        p1 = models.Package.objects.create(type="deb", name="git", version="2.30.1")
        p2 = models.Package.objects.create(type="deb", name="git", version="2.31.1")
        v1 = models.Vulnerability.objects.create(vulnerability_id="CVE-123-2002")

        prv1 = models.PackageRelatedVulnerability.objects.create(
            patched_package=p2, package=p1, vulnerability=v1
        )

        assert v1.vulnerable_packages.all().count() == 1
        assert v1.patched_packages.all().count() == 1

        assert v1.vulnerable_packages.all()[0] == p1
        assert v1.patched_packages.all()[0] == p2
