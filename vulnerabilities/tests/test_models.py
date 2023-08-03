#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from datetime import datetime
from unittest import TestCase

import pytest
from django.db.utils import IntegrityError
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

    def test_cwe_not_present_in_weaknesses_db(self):
        w1 = models.Weakness.objects.create(name="189")
        assert w1.weakness is None
        assert w1.name is ""
        assert w1.description is ""
