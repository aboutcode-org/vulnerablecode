#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
import time

import pytest
from django.test import Client
from django.test import TestCase
from packageurl import PackageURL
from univers import versions

from vulnerabilities.models import AffectedByPackageRelatedVulnerability
from vulnerabilities.models import Alias
from vulnerabilities.models import FixingPackageRelatedVulnerability
from vulnerabilities.models import Package
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilitySeverity
from vulnerabilities.templatetags.url_filters import url_quote_filter
from vulnerabilities.utils import get_purl_version_class
from vulnerabilities.views import PackageDetails
from vulnerabilities.views import PackageSearch

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DIR = os.path.join(BASE_DIR, "test_data/package_sort")


class PackageSearchTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        packages = [
            "pkg:nginx/nginx@0.6.18",
            "pkg:nginx/nginx@1.20.0",
            "pkg:nginx/nginx@1.21.0",
            "pkg:nginx/nginx@1.20.1",
            "pkg:nginx/nginx@1.9.5",
            "pkg:nginx/nginx@1.17.2",
            "pkg:nginx/nginx@1.17.3",
            "pkg:nginx/nginx@1.16.1",
            "pkg:nginx/nginx@1.15.5",
            "pkg:nginx/nginx@1.15.6",
            "pkg:nginx/nginx@1.14.1",
            "pkg:nginx/nginx@1.0.7",
            "pkg:nginx/nginx@1.0.15",
            "pkg:nginx/nginx@1.0.15?foo=bar",
            "pkg:pypi/foo@1",
        ]
        self.packages = packages
        for package in packages:
            purl = PackageURL.from_string(package)
            attrs = {k: v for k, v in purl.to_dict().items() if v}
            Package.objects.create(**attrs)

    def test_packages_search_view_paginator(self):
        response = self.client.get("/packages/search/?type=deb&name=&page=1")
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/packages/search/?type=deb&name=&page=*")
        self.assertEqual(response.status_code, 404)
        response = self.client.get("/packages/search/?type=deb&name=&page=")
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/packages/search/?type=&name=&page=")
        self.assertEqual(response.status_code, 200)

    def test_package_view(self):
        qs = PackageSearch().get_queryset(query="pkg:nginx/nginx@1.0.15?foo=bar")
        pkgs = list(qs)
        self.assertEqual(len(pkgs), 2)
        self.assertEqual(pkgs[0].purl, "pkg:nginx/nginx@1.0.15")

    def test_package_detail_view(self):
        package = PackageDetails(kwargs={"purl": "pkg:nginx/nginx@1.0.15"}).get_object()
        assert package.purl == "pkg:nginx/nginx@1.0.15"

    def test_package_view_with_purl_fragment(self):
        qs = PackageSearch().get_queryset(query="nginx@1.0.15")
        pkgs = list(qs)
        self.assertEqual(len(pkgs), 2)
        self.assertEqual(pkgs[0].purl, "pkg:nginx/nginx@1.0.15")
        self.assertEqual(pkgs[1].purl, "pkg:nginx/nginx@1.0.15?foo=bar")

    def test_package_view_with_purl_fragment_2(self):
        qs = PackageSearch().get_queryset(query="nginx/nginx")
        pkgs = list(qs)
        pkgs = [p.purl for p in pkgs]
        expected = [
            "pkg:nginx/nginx@0.6.18",
            "pkg:nginx/nginx@1.0.15",
            "pkg:nginx/nginx@1.0.15?foo=bar",
            "pkg:nginx/nginx@1.0.7",
            "pkg:nginx/nginx@1.14.1",
            "pkg:nginx/nginx@1.15.5",
            "pkg:nginx/nginx@1.15.6",
            "pkg:nginx/nginx@1.16.1",
            "pkg:nginx/nginx@1.17.2",
            "pkg:nginx/nginx@1.17.3",
            "pkg:nginx/nginx@1.20.0",
            "pkg:nginx/nginx@1.20.1",
            "pkg:nginx/nginx@1.21.0",
            "pkg:nginx/nginx@1.9.5",
        ]
        assert pkgs == expected

    def test_package_view_with_valid_purl_without_version(self):
        qs = PackageSearch().get_queryset(query="pkg:nginx/nginx")
        pkgs = list(qs)
        pkgs = [p.purl for p in pkgs]
        assert pkgs == [
            "pkg:nginx/nginx@0.6.18",
            "pkg:nginx/nginx@1.0.15",
            "pkg:nginx/nginx@1.0.15?foo=bar",
            "pkg:nginx/nginx@1.0.7",
            "pkg:nginx/nginx@1.14.1",
            "pkg:nginx/nginx@1.15.5",
            "pkg:nginx/nginx@1.15.6",
            "pkg:nginx/nginx@1.16.1",
            "pkg:nginx/nginx@1.17.2",
            "pkg:nginx/nginx@1.17.3",
            "pkg:nginx/nginx@1.20.0",
            "pkg:nginx/nginx@1.20.1",
            "pkg:nginx/nginx@1.21.0",
            "pkg:nginx/nginx@1.9.5",
        ]

    def test_package_view_with_valid_purl_and_incomplete_version(self):
        qs = PackageSearch().get_queryset(query="pkg:nginx/nginx@1")
        pkgs = list(qs)
        pkgs = [p.purl for p in pkgs]
        assert pkgs == [
            "pkg:nginx/nginx@1.0.15",
            "pkg:nginx/nginx@1.0.15?foo=bar",
            "pkg:nginx/nginx@1.0.7",
            "pkg:nginx/nginx@1.14.1",
            "pkg:nginx/nginx@1.15.5",
            "pkg:nginx/nginx@1.15.6",
            "pkg:nginx/nginx@1.16.1",
            "pkg:nginx/nginx@1.17.2",
            "pkg:nginx/nginx@1.17.3",
            "pkg:nginx/nginx@1.20.0",
            "pkg:nginx/nginx@1.20.1",
            "pkg:nginx/nginx@1.21.0",
            "pkg:nginx/nginx@1.9.5",
        ]

    def test_package_view_with_purl_type(self):
        qs = PackageSearch().get_queryset(query="pkg:pypi")
        pkgs = list(qs)
        pkgs = [p.purl for p in pkgs]
        assert pkgs == ["pkg:pypi/foo@1"]

    def test_package_view_with_type_as_input(self):
        qs = PackageSearch().get_queryset(query="pypi")
        pkgs = list(qs)
        pkgs = [p.purl for p in pkgs]
        assert pkgs == ["pkg:pypi/foo@1"]


class VulnerabilitySearchTestCase(TestCase):
    def setUp(self):
        self.vulnerability = vulnerability = Vulnerability(summary="test")
        vulnerability.save()
        alias = Alias(alias="TEST-2022", vulnerability=vulnerability)
        alias.save()
        self.client = Client()

    def test_vulnerabilties_search_view_with_vcid_works_and_pk_does_not(self):
        response = self.client.get(f"/vulnerabilities/{self.vulnerability.pk}")
        self.assertEqual(response.status_code, 404)
        response = self.client.get(f"/vulnerabilities/{self.vulnerability.vulnerability_id}")
        self.assertEqual(response.status_code, 200)

    def test_vulnerabilties_search_view_with_empty(self):
        response = self.client.get(f"/vulnerabilities/search/")
        self.assertEqual(response.status_code, 200)

    def test_vulnerabilties_search_view_can_find_alias(self):
        response = self.client.get(f"/vulnerabilities/search/?search=TEST-2022")
        self.assertEqual(response.status_code, 200)


class CheckRobotsTxtTestCase(TestCase):
    def test_robots_txt(self):
        response = self.client.get("/robots.txt")
        assert response.status_code == 200
        response = self.client.post("/robots.txt")
        assert response.status_code == 405


class TestPackageSortTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        TEST_DATA = os.path.join(TEST_DIR, "input_purls.txt")
        with open(TEST_DATA) as f:
            input_purls = [l for l in f.readlines()]
        self.input_purls = input_purls
        for pkg in input_purls:
            real_purl = PackageURL.from_string(pkg)
            attrs = {k: v for k, v in real_purl.to_dict().items() if v}
            pkg = Package.objects.create(**attrs)
            pkg.calculate_version_rank

    def test_sorted_queryset(self):
        qs_all = Package.objects.all()
        pkgs_qs_all = list(qs_all)
        sorted_pkgs_qs_all = pkgs_qs_all

        pkg_package_urls = [obj.package_url for obj in sorted_pkgs_qs_all]
        sorted_purls = os.path.join(TEST_DIR, "sorted_purls.txt")
        with open(sorted_purls, "r") as f:
            expected_content = f.read().splitlines()
            assert pkg_package_urls == expected_content

    def test_get_purl_version_class(self):
        test_cases = {
            "pkg:alpm/arch/containers-common@1:0.47.4-4?arch=x86_64": versions.ArchLinuxVersion,
            "pkg:cargo/clap@3.0.0": versions.SemverVersion,
            "pkg:composer/bk2k/bootstrap-package@7.1.0": versions.ComposerVersion,
            "pkg:conan/capnproto@0.7.0": versions.ConanVersion,
            "pkg:deb/debian/jackson-databind@2.8.6-1%2Bdeb9u7?distro=stretch": versions.DebianVersion,
            "pkg:deb/ubuntu/dpkg@1.13.11ubuntu7~proposed": versions.DebianVersion,
            "pkg:gem/actionpack@3.1.1": versions.RubygemsVersion,
            "pkg:generic/postgresql@10.2.0": versions.SemverVersion,
            "pkg:github/istio/istio@0.2.0": versions.SemverVersion,
            "pkg:golang/github.com/1Panel-dev/1Panel@1.3.6": versions.GolangVersion,
            "pkg:hex/pow@1.0.2": versions.SemverVersion,
            "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.1.1": versions.MavenVersion,
            "pkg:npm/bootstrap-select@1.6.2": versions.SemverVersion,
            "pkg:nuget/adplug@2.3.0-beta17": versions.NugetVersion,
            "pkg:pypi/jinja2@2.1": versions.PypiVersion,
            "pkg:rpm/redhat/openssl@1.0.1e-30.el6_6?arch=11": versions.RpmVersion,
        }
        for k in test_cases:
            pkg = Package.objects.get(package_url=k)
            assert get_purl_version_class(pkg) == test_cases.get(k)


class TestCustomFilters:
    @pytest.mark.parametrize(
        "input_value, expected_output",
        [
            (
                "pkg:rpm/redhat/katello-client-bootstrap@1.1.0-2?arch=el6sat",
                "pkg%3Arpm/redhat/katello-client-bootstrap%401.1.0-2%3Farch%3Del6sat",
            ),
            (
                "pkg:apk/alpine/nginx@1.10.3-r1?arch=armhf&distroversion=v3.5&reponame=main",
                "pkg%3Aapk/alpine/nginx%401.10.3-r1%3Farch%3Darmhf%26distroversion%3Dv3.5%26reponame%3Dmain",
            ),
            ("pkg:nginx/nginx@0.9.0?os=windows", "pkg%3Anginx/nginx%400.9.0%3Fos%3Dwindows"),
            (
                "pkg:deb/ubuntu/nginx@0.6.34-2ubuntu1~intrepid1",
                "pkg%3Adeb/ubuntu/nginx%400.6.34-2ubuntu1~intrepid1",
            ),
            (
                "pkg:rpm/redhat/openssl@1:1.0.2k-16.el7_6?arch=1",
                "pkg%3Arpm/redhat/openssl%401%3A1.0.2k-16.el7_6%3Farch%3D1",
            ),
            (
                "pkg:golang/google.golang.org/genproto#googleapis/api/annotations",
                "pkg%3Agolang/google.golang.org/genproto%23googleapis/api/annotations",
            ),
            (
                "pkg:cocoapods/GoogleUtilities@7.5.2#NSData+zlib",
                "pkg%3Acocoapods/GoogleUtilities%407.5.2%23NSData%2Bzlib",
            ),
            (
                "pkg:conda/absl-py@0.4.1?build=py36h06a4308_0&channel=main&subdir=linux-64&type=tar.bz2",
                "pkg%3Aconda/absl-py%400.4.1%3Fbuild%3Dpy36h06a4308_0%26channel%3Dmain%26subdir%3Dlinux-64%26type%3Dtar.bz2",
            ),
        ],
    )
    def test_url_quote_filter(self, input_value, expected_output):
        filtered = url_quote_filter(input_value)
        assert filtered == expected_output


class VulnerabilitySearchTestCaseWithPackages(TestCase):
    def setUp(self):
        self.vuln1 = Vulnerability.objects.create(vulnerability_id="VCID-1", summary="Vuln 1")
        self.vuln2 = Vulnerability.objects.create(vulnerability_id="VCID-2", summary="Vuln 2")
        self.vuln3 = Vulnerability.objects.create(vulnerability_id="VCID-3", summary="Vuln 3")
        self.vuln4 = Vulnerability.objects.create(vulnerability_id="VCID-4", summary="Vuln 4")
        self.vuln5 = Vulnerability.objects.create(vulnerability_id="VCID-5", summary="Vuln 5")

        self.package1 = Package.objects.create(type="pypi", name="django", version="1.0.0")
        self.package2 = Package.objects.create(type="pypi", name="django", version="2.0.0")
        self.package3 = Package.objects.create(type="pypi", name="django", version="3.0.0")

        AffectedByPackageRelatedVulnerability.objects.create(
            package=self.package1, vulnerability=self.vuln1
        )
        AffectedByPackageRelatedVulnerability.objects.create(
            package=self.package1, vulnerability=self.vuln2
        )
        AffectedByPackageRelatedVulnerability.objects.create(
            package=self.package2, vulnerability=self.vuln3
        )
        AffectedByPackageRelatedVulnerability.objects.create(
            package=self.package2, vulnerability=self.vuln4
        )

        FixingPackageRelatedVulnerability.objects.create(
            package=self.package3, vulnerability=self.vuln5
        )

        self.severity1 = VulnerabilitySeverity.objects.create(
            scoring_system="CVSSv3",
            value="9.8",
            scoring_elements="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        self.severity2 = VulnerabilitySeverity.objects.create(
            scoring_system="CVSSv3",
            value="7.5",
            scoring_elements="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )

        self.vuln1.severities.add(self.severity1)
        self.vuln1.severities.add(self.severity2)
        self.vuln1.save()

    def test_aggregate_fixed_and_affected_packages(self):
        with self.assertNumQueries(11):
            start_time = time.time()
            response = self.client.get(f"/vulnerabilities/{self.vuln1.vulnerability_id}")
            end_time = time.time()
            assert end_time - start_time < 0.05
            self.assertEqual(response.status_code, 200)
