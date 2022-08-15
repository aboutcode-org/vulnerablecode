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
from packageurl import PackageURL
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
        self.pkg1 = Package.objects.create(name="flask", type="pypi", version="0.1.2")
        self.pkg2 = Package.objects.create(name="flask", type="debian", version="0.1.2")
        for pkg in [self.pkg1, self.pkg2]:
            PackageRelatedVulnerability.objects.create(
                package=pkg, vulnerability=self.vulnerability, fix=True
            )

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
            "fixed_packages": [
                {
                    "url": f"http://testserver/api/packages/{self.pkg1.id}",
                    "purl": "pkg:pypi/flask@0.1.2",
                },
                {
                    "url": f"http://testserver/api/packages/{self.pkg2.id}",
                    "purl": "pkg:debian/flask@0.1.2",
                },
            ],
            "affected_packages": [],
            "references": [],
        }

    def test_api_with_single_vulnerability_with_filters(self):
        response = self.client.get(
            f"/api/vulnerabilities/{self.vulnerability.id}?type=pypi", format="json"
        ).data
        assert response == {
            "url": f"http://testserver/api/vulnerabilities/{self.vulnerability.id}",
            "vulnerability_id": f"VULCOID-{int_to_base36(self.vulnerability.id).upper()}",
            "summary": "test",
            "aliases": [],
            "fixed_packages": [
                {
                    "url": f"http://testserver/api/packages/{self.pkg1.id}",
                    "purl": "pkg:pypi/flask@0.1.2",
                },
            ],
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
            "qualifiers": {},
            "subpath": "",
            "affected_by_vulnerabilities": [],
            "fixing_vulnerabilities": [
                {
                    "url": f"http://testserver/api/vulnerabilities/{self.vuln.id}",
                    "vulnerability_id": f"VULCOID-{int_to_base36(self.vuln.id).upper()}",
                    "summary": "test-vuln",
                    "references": [],
                    "fixed_packages": [
                        {
                            "url": f"http://testserver/api/packages/{self.package.id}",
                            "purl": "pkg:generic/nginx/test@11",
                        }
                    ],
                },
            ],
            "unresolved_vulnerabilities": [],
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
            "qualifiers": {},
            "subpath": "",
            "affected_by_vulnerabilities": [
                {
                    "url": f"http://testserver/api/vulnerabilities/{self.vuln.id}",
                    "vulnerability_id": f"VULCOID-{int_to_base36(self.vuln.id).upper()}",
                    "summary": "test-vuln",
                    "references": [],
                    "fixed_packages": [
                        {
                            "url": f"http://testserver/api/packages/{self.package.id}",
                            "purl": "pkg:generic/nginx/test@11",
                        }
                    ],
                }
            ],
            "fixing_vulnerabilities": [],
            "unresolved_vulnerabilities": [
                {
                    "url": f"http://testserver/api/vulnerabilities/{self.vuln.id}",
                    "vulnerability_id": f"VULCOID-{int_to_base36(self.vuln.id).upper()}",
                    "summary": "test-vuln",
                    "references": [],
                    "fixed_packages": [
                        {
                            "url": f"http://testserver/api/packages/{self.package.id}",
                            "purl": "pkg:generic/nginx/test@11",
                        }
                    ],
                }
            ],
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


class BulkSearchAPI(TestCase):
    def setUp(self):
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
        ]
        self.packages = packages
        for package in packages:
            purl = PackageURL.from_string(package)
            attrs = {k: v for k, v in purl.to_dict().items() if v}
            Package.objects.create(**attrs)

    def test_api_response(self):
        request_body = {
            "purls": self.packages,
        }
        response = self.client.post(
            "/api/packages/bulk_search",
            data=request_body,
            content_type="application/json",
        ).json()
        assert len(response) == 13


class BulkSearchAPI(TestCase):
    def setUp(self):
        cpes = [
            "cpe:/a:nginx:1.0.7",
            "cpe:/a:nginx:1.0.15",
            "cpe:/a:nginx:1.14.1",
            "cpe:/a:nginx:1.15.5",
            "cpe:/a:nginx:1.15.6",
            "cpe:/a:nginx:1.16.1",
            "cpe:/a:nginx:1.17.2",
            "cpe:/a:nginx:1.17.3",
            "cpe:/a:nginx:1.9.5",
            "cpe:/a:nginx:1.20.1",
            "cpe:/a:nginx:1.20.0",
            "cpe:/a:nginx:1.21.0",
        ]
        self.cpes = cpes
        vuln = Vulnerability.objects.create(summary="test")
        for cpe in cpes:
            ref = VulnerabilityReference.objects.create(reference_id=cpe)
            VulnerabilityRelatedReference.objects.create(reference=ref, vulnerability=vuln)

    def test_api_response_with_one_vulnerability(self):
        request_body = {
            "cpes": self.cpes,
        }
        response = self.client.post(
            "/api/cpes/bulk_search",
            data=request_body,
            content_type="application/json",
        ).json()
        assert len(response) == 1
