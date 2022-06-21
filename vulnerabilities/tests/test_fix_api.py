#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.test import TestCase
from django.utils.http import int_to_base36
from rest_framework import status

from vulnerabilities.models import Alias
from vulnerabilities.models import Package
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilityRelatedReference


class APITestCaseVulnerability(TestCase):
    def setUp(self):
        for i in range(0, 200):
            Vulnerability.objects.create(
                summary=str(i),
            )
        self.vulnerability = Vulnerability.objects.create(summary="test")

    def test_api_status(self):
        response = self.client.get("/api/vulnerabilities/", format="json")
        self.assertEqual(status.HTTP_200_OK, response.status_code)

    def test_api_response(self):
        response = self.client.get("/api/vulnerabilities/", format="json").data
        self.assertEqual(response["count"], 201)

    def test_api_with_single_vulnerability(self):
        response = self.client.get(
            f"/api/vulnerabilities/{self.vulnerability.id}", format="json"
        ).data
        assert response == {
            "url": f"http://testserver/api/vulnerabilities/{self.vulnerability.id}",
            "vulnerability_id": f"VULCOID-{int_to_base36(self.vulnerability.id).upper()}",
            "summary": "test",
            "aliases": [],
            "fixed_packages": [],
            "affected_packages": [],
            "references": [],
        }


class APITestCasePackage(TestCase):
    def setUp(self):
        for i in range(0, 10):
            query_kwargs = dict(
                type="generic",
                namespace="nginx",
                name=f"test-{i}",
                version=str(i),
                qualifiers={},
                subpath="",
            )
            Package.objects.create(**query_kwargs)
        query_kwargs = dict(
            type="generic",
            namespace="nginx",
            name="test-vulnDB",
            version="1.0",
            qualifiers={},
            subpath="",
        )
        self.package = Package.objects.create(**query_kwargs)

    def test_api_status(self):
        response = self.client.get("/api/packages/", format="json")
        self.assertEqual(status.HTTP_200_OK, response.status_code)

    def test_api_response(self):
        response = self.client.get("/api/packages/", format="json").data
        self.assertEqual(response["count"], 11)

    def test_api_with_single_vulnerability(self):
        response = self.client.get(f"/api/packages/{self.package.id}", format="json").data
        assert response == {
            "url": f"http://testserver/api/packages/{self.package.id}",
            "purl": "pkg:generic/nginx/test-vulnDB@1.0",
            "type": "generic",
            "namespace": "nginx",
            "name": "test-vulnDB",
            "version": "1.0",
            "unresolved_vulnerabilities": [],
            "qualifiers": {},
            "subpath": "",
            "affected_by_vulnerabilities": [],
            "fixing_vulnerabilities": [],
        }


class CPEApi(TestCase):
    def setUp(self):
        self.vulnerability = Vulnerability.objects.create(summary="test")
        for i in range(0, 10):
            ref, _ = VulnerabilityReference.objects.get_or_create(
                reference_id=f"cpe:/a:nginx:{i}",
            )
            VulnerabilityRelatedReference.objects.create(
                reference=ref, vulnerability=self.vulnerability
            )

    def test_api_status(self):
        response = self.client.get("/api/cpes/", format="json")
        self.assertEqual(status.HTTP_200_OK, response.status_code)

    def test_api_response(self):
        response = self.client.get("/api/cpes/?cpe=cpe:/a:nginx:9", format="json").data
        self.assertEqual(response["count"], 1)


class AliasApi(TestCase):
    def setUp(self):
        self.vulnerability = Vulnerability.objects.create(summary="test")
        for i in range(0, 10):
            Alias.objects.create(alias=f"CVE-{i}", vulnerability=self.vulnerability)

    def test_api_status(self):
        response = self.client.get("/api/alias/", format="json")
        self.assertEqual(status.HTTP_200_OK, response.status_code)

    def test_api_response(self):
        response = self.client.get("/api/alias?alias=CVE-9", format="json").data
        self.assertEqual(response["count"], 1)
