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
from vulnerabilities.models import PackageRelatedVulnerability
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
        vuln = Vulnerability.objects.create(
            summary="test-vuln",
        )
        self.vuln = vuln
        for i in range(0, 10):
            query_kwargs = dict(
                type="generic",
                namespace="nginx",
                name="test",
                version=str(i),
                qualifiers={},
                subpath="",
            )
            vuln_package = Package.objects.create(**query_kwargs)
            PackageRelatedVulnerability.objects.create(
                package=vuln_package,
                vulnerability=vuln,
                fix=False,
            )
        self.vuln_package = vuln_package
        query_kwargs = dict(
            type="generic",
            namespace="nginx",
            name="test",
            version="11",
            qualifiers={},
            subpath="",
        )
        self.package = Package.objects.create(**query_kwargs)
        PackageRelatedVulnerability.objects.create(
            package=self.package,
            vulnerability=vuln,
            fix=True,
        )

    def test_api_status(self):
        response = self.client.get("/api/packages/", format="json")
        self.assertEqual(status.HTTP_200_OK, response.status_code)

    def test_api_response(self):
        response = self.client.get("/api/packages/", format="json").data
        self.assertEqual(response["count"], 11)

    def test_api_with_single_vulnerability_and_fixed_package(self):
        response = self.client.get(f"/api/packages/{self.package.id}", format="json").data
        assert response == {
            "url": f"http://testserver/api/packages/{self.package.id}",
            "purl": "pkg:generic/nginx/test@11",
            "type": "generic",
            "namespace": "nginx",
            "name": "test",
            "version": "11",
            "unresolved_vulnerabilities": [],
            "qualifiers": {},
            "subpath": "",
            "fixed_packages": [
                {
                    "url": f"http://testserver/api/packages/{self.package.id}",
                    "purl": "pkg:generic/nginx/test@11",
                    "fixing_vulnerabilities": [
                        {
                            "url": f"http://testserver/api/vulnerabilities/{self.vuln.id}",
                            "vulnerability_id": f"VULCOID-{int_to_base36(self.vuln.id).upper()}",
                        }
                    ],
                }
            ],
            "affected_by_vulnerabilities": [],
            "fixing_vulnerabilities": [
                {
                    "url": f"http://testserver/api/vulnerabilities/{self.vuln.id}",
                    "vulnerability_id": f"VULCOID-{int_to_base36(self.vuln.id).upper()}",
                    "summary": "test-vuln",
                    "references": [],
                }
            ],
        }

    def test_api_with_single_vulnerability_and_vulnerable_package(self):
        response = self.client.get(f"/api/packages/{self.vuln_package.id}", format="json").data
        assert response == {
            "url": f"http://testserver/api/packages/{self.vuln_package.id}",
            "purl": "pkg:generic/nginx/test@9",
            "type": "generic",
            "namespace": "nginx",
            "name": "test",
            "version": "9",
            "unresolved_vulnerabilities": [
                {
                    "url": f"http://testserver/api/vulnerabilities/{self.vuln.id}",
                    "vulnerability_id": f"VULCOID-{int_to_base36(self.vuln.id).upper()}",
                    "summary": "test-vuln",
                    "references": [],
                }
            ],
            "qualifiers": {},
            "subpath": "",
            "fixed_packages": [
                {
                    "url": f"http://testserver/api/packages/{self.package.id}",
                    "purl": "pkg:generic/nginx/test@11",
                    "fixing_vulnerabilities": [
                        {
                            "url": f"http://testserver/api/vulnerabilities/{self.vuln.id}",
                            "vulnerability_id": f"VULCOID-{int_to_base36(self.vuln.id).upper()}",
                        }
                    ],
                }
            ],
            "affected_by_vulnerabilities": [
                {
                    "url": f"http://testserver/api/vulnerabilities/{self.vuln.id}",
                    "vulnerability_id": f"VULCOID-{int_to_base36(self.vuln.id).upper()}",
                    "summary": "test-vuln",
                    "references": [],
                }
            ],
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
