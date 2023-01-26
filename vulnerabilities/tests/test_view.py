#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.test import Client
from django.test import TestCase
from packageurl import PackageURL

from vulnerabilities.models import Alias
from vulnerabilities.models import Package
from vulnerabilities.models import Vulnerability
from vulnerabilities.views import PackageDetails
from vulnerabilities.views import PackageSearch


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
        response = self.client.get("/packages/search?type=deb&name=&page=1")
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/packages/search?type=deb&name=&page=*")
        self.assertEqual(response.status_code, 404)
        response = self.client.get("/packages/search?type=deb&name=&page=")
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/packages/search?type=&name=&page=")
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
        self.assertEqual(len(pkgs), 1)
        self.assertEqual(pkgs[0].purl, "pkg:nginx/nginx@1.0.15")

    def test_package_view_with_purl_fragment(self):
        qs = PackageSearch().get_queryset(query="nginx/nginx")
        pkgs = list(qs)
        pkgs = [p.purl for p in pkgs]
        assert pkgs == [
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
        ]

    def test_package_view_with_valid_purl_without_version(self):
        qs = PackageSearch().get_queryset(query="pkg:nginx/nginx")
        pkgs = list(qs)
        pkgs = [p.purl for p in pkgs]
        assert pkgs == [
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
        ]

    def test_package_view_with_valid_purl_and_incomplete_version(self):
        qs = PackageSearch().get_queryset(query="pkg:nginx/nginx@1")
        pkgs = list(qs)
        pkgs = [p.purl for p in pkgs]
        assert pkgs == [
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
        response = self.client.get(f"/vulnerabilities/search")
        self.assertEqual(response.status_code, 200)

    def test_vulnerabilties_search_view_can_find_alias(self):
        response = self.client.get(f"/vulnerabilities/search?search=TEST-2022")
        self.assertEqual(response.status_code, 200)
