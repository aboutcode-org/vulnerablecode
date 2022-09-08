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

from vulnerabilities.models import Alias
from vulnerabilities.models import Vulnerability


class PackageSearchTestCase(TestCase):
    def setUp(self):
        self.client = Client()

    def test_packages_search_view_paginator(self):
        response = self.client.get("/packages/search?type=deb&name=&page=1")
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/packages/search?type=deb&name=&page=*")
        self.assertEqual(response.status_code, 404)
        response = self.client.get("/packages/search?type=deb&name=&page=")
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/packages/search?type=&name=&page=")
        self.assertEqual(response.status_code, 200)


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
