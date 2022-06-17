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

    def test_paginator(self):
        """
        Test PackageSearch paginator
        """
        response = self.client.get("/packages/search?type=deb&name=&page=1")
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/packages/search?type=deb&name=&page=*")
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/packages/search?type=deb&name=&page=")
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/packages/search?type=&name=&page=")
        self.assertEqual(response.status_code, 200)


class VulnerabilitySearchTestCase(TestCase):
    def setUp(self):
        vulnerability = Vulnerability(summary="test")
        vulnerability.save()
        alias = Alias(alias="TEST-2022", vulnerability=vulnerability)
        alias.save()
        self.id = vulnerability.id
        self.client = Client()

    def test_vulnerabilties(self):
        """
        Test Vulnerability View
        """
        response = self.client.get(f"/vulnerabilities/{self.id}")
        self.assertEqual(response.status_code, 200)

    def test_vulnerabilties_search(self):
        """
        Test Vulnerability Search View
        """
        response = self.client.get(f"/vulnerabilities/search")
        self.assertEqual(response.status_code, 200)

    def test_alias(self):
        """
        Test Vulnerability Search View
        """
        response = self.client.get(f"/vulnerabilities/search?vuln_id=TEST-2022")
        self.assertEqual(response.status_code, 200)
