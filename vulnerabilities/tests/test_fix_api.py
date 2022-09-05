#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.test import TransactionTestCase
from django.utils.http import int_to_base36
from packageurl import PackageURL
from rest_framework import status
from rest_framework.test import APIClient

from vulnerabilities.models import Alias
from vulnerabilities.models import Package
from vulnerabilities.models import PackageRelatedVulnerability
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilityRelatedReference

User = get_user_model()


class APITestCaseVulnerability(TransactionTestCase):
    def setUp(self):
        self.user = User.objects.create_user("username", "e@mail.com", "secret")
        self.auth = f"Token {self.user.auth_token.key}"
        self.csrf_client = APIClient(enforce_csrf_checks=True)
        self.csrf_client.credentials(HTTP_AUTHORIZATION=self.auth)
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
        response = self.csrf_client.get("/api/vulnerabilities/")
        self.assertEqual(status.HTTP_200_OK, response.status_code)

    def test_api_response(self):
        response = self.csrf_client.get("/api/vulnerabilities/").data
        self.assertEqual(response["count"], 201)

    def test_api_with_single_vulnerability(self):
        response = self.csrf_client.get(
            f"/api/vulnerabilities/{self.vulnerability.id}", format="json"
        ).data
        assert response == {
            "url": f"http://testserver/api/vulnerabilities/{self.vulnerability.id}",
            "vulnerability_id": self.vulnerability.vulnerability_id,
            "summary": "test",
            "aliases": [],
            "fixed_packages": [
                {
                    "url": f"http://testserver/api/packages/{self.pkg1.id}",
                    "purl": "pkg:pypi/flask@0.1.2",
                    "is_vulnerable": False,
                },
                {
                    "url": f"http://testserver/api/packages/{self.pkg2.id}",
                    "purl": "pkg:debian/flask@0.1.2",
                    "is_vulnerable": False,
                },
            ],
            "affected_packages": [],
            "references": [],
        }

    def test_api_with_single_vulnerability_with_filters(self):
        response = self.csrf_client.get(
            f"/api/vulnerabilities/{self.vulnerability.id}?type=pypi", format="json"
        ).data
        assert response == {
            "url": f"http://testserver/api/vulnerabilities/{self.vulnerability.id}",
            "vulnerability_id": self.vulnerability.vulnerability_id,
            "summary": "test",
            "aliases": [],
            "fixed_packages": [
                {
                    "url": f"http://testserver/api/packages/{self.pkg1.id}",
                    "purl": "pkg:pypi/flask@0.1.2",
                    "is_vulnerable": False,
                },
            ],
            "affected_packages": [],
            "references": [],
        }


class APITestCasePackage(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("username", "e@mail.com", "secret")
        self.auth = f"Token {self.user.auth_token.key}"
        self.csrf_client = APIClient(enforce_csrf_checks=True)
        self.csrf_client.credentials(HTTP_AUTHORIZATION=self.auth)
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
        vuln1 = Vulnerability.objects.create(
            summary="test-vuln1",
        )
        self.vuln1 = vuln1
        PackageRelatedVulnerability.objects.create(
            package=self.package,
            vulnerability=vuln1,
            fix=False,
        )

    def test_is_vulnerable_attribute(self):
        self.assertTrue(self.package.is_vulnerable)

    def test_api_status(self):
        response = self.csrf_client.get("/api/packages/", format="json")
        self.assertEqual(status.HTTP_200_OK, response.status_code)

    def test_api_response(self):
        response = self.csrf_client.get("/api/packages/", format="json").data
        self.assertEqual(response["count"], 11)

    def test_api_with_namespace_filter(self):
        response = self.csrf_client.get("/api/packages/?namespace=nginx", format="json").data
        self.assertEqual(response["count"], 11)

    def test_api_with_wrong_namespace_filter(self):
        response = self.csrf_client.get("/api/packages/?namespace=foo-bar", format="json").data
        self.assertEqual(response["count"], 0)

    def test_api_with_single_vulnerability_and_fixed_package(self):
        response = self.csrf_client.get(f"/api/packages/{self.package.id}", format="json").data
        assert response == {
            "url": f"http://testserver/api/packages/{self.package.id}",
            "purl": "pkg:generic/nginx/test@11",
            "type": "generic",
            "namespace": "nginx",
            "name": "test",
            "version": "11",
            "qualifiers": {},
            "subpath": "",
            "affected_by_vulnerabilities": [
                {
                    "url": f"http://testserver/api/vulnerabilities/{self.vuln1.id}",
                    "vulnerability_id": self.vuln1.vulnerability_id,
                    "summary": "test-vuln1",
                    "references": [],
                    "fixed_packages": [],
                }
            ],
            "fixing_vulnerabilities": [
                {
                    "url": f"http://testserver/api/vulnerabilities/{self.vuln.id}",
                    "vulnerability_id": self.vuln.vulnerability_id,
                    "summary": "test-vuln",
                    "references": [],
                    "fixed_packages": [
                        {
                            "url": f"http://testserver/api/packages/{self.package.id}",
                            "purl": "pkg:generic/nginx/test@11",
                            "is_vulnerable": True,
                        }
                    ],
                },
            ],
            "unresolved_vulnerabilities": [
                {
                    "url": f"http://testserver/api/vulnerabilities/{self.vuln1.id}",
                    "vulnerability_id": self.vuln1.vulnerability_id,
                    "summary": "test-vuln1",
                    "references": [],
                    "fixed_packages": [],
                }
            ],
        }

    def test_api_with_single_vulnerability_and_vulnerable_package(self):
        response = self.csrf_client.get(f"/api/packages/{self.vuln_package.id}", format="json").data
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
                    "vulnerability_id": self.vuln.vulnerability_id,
                    "summary": "test-vuln",
                    "references": [],
                    "fixed_packages": [
                        {
                            "url": f"http://testserver/api/packages/{self.package.id}",
                            "purl": "pkg:generic/nginx/test@11",
                            "is_vulnerable": True,
                        }
                    ],
                }
            ],
            "fixing_vulnerabilities": [],
            "unresolved_vulnerabilities": [
                {
                    "url": f"http://testserver/api/vulnerabilities/{self.vuln.id}",
                    "vulnerability_id": self.vuln.vulnerability_id,
                    "summary": "test-vuln",
                    "references": [],
                    "fixed_packages": [
                        {
                            "url": f"http://testserver/api/packages/{self.package.id}",
                            "purl": "pkg:generic/nginx/test@11",
                            "is_vulnerable": True,
                        }
                    ],
                }
            ],
        }


class CPEApi(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("username", "e@mail.com", "secret")
        self.auth = f"Token {self.user.auth_token.key}"
        self.csrf_client = APIClient(enforce_csrf_checks=True)
        self.csrf_client.credentials(HTTP_AUTHORIZATION=self.auth)
        self.vulnerability = Vulnerability.objects.create(summary="test")
        for i in range(0, 10):
            ref, _ = VulnerabilityReference.objects.get_or_create(
                reference_id=f"cpe:/a:nginx:{i}",
            )
            VulnerabilityRelatedReference.objects.create(
                reference=ref, vulnerability=self.vulnerability
            )

    def test_api_status(self):
        response = self.csrf_client.get("/api/cpes/", format="json")
        self.assertEqual(status.HTTP_200_OK, response.status_code)

    def test_api_response(self):
        response = self.csrf_client.get("/api/cpes/?cpe=cpe:/a:nginx:9", format="json").data
        self.assertEqual(response["count"], 1)


class AliasApi(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("username", "e@mail.com", "secret")
        self.auth = f"Token {self.user.auth_token.key}"
        self.csrf_client = APIClient(enforce_csrf_checks=True)
        self.csrf_client.credentials(HTTP_AUTHORIZATION=self.auth)
        self.vulnerability = Vulnerability.objects.create(summary="test")
        for i in range(0, 10):
            Alias.objects.create(alias=f"CVE-{i}", vulnerability=self.vulnerability)

    def test_api_status(self):
        response = self.csrf_client.get("/api/alias/", format="json")
        self.assertEqual(status.HTTP_200_OK, response.status_code)

    def test_api_response(self):
        response = self.csrf_client.get("/api/alias?alias=CVE-9", format="json").data
        self.assertEqual(response["count"], 1)


class BulkSearchAPIPackage(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("username", "e@mail.com", "secret")
        self.auth = f"Token {self.user.auth_token.key}"
        self.csrf_client = APIClient(enforce_csrf_checks=True)
        self.csrf_client.credentials(HTTP_AUTHORIZATION=self.auth)
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
        response = self.csrf_client.post(
            "/api/packages/bulk_search",
            data=json.dumps(request_body),
            content_type="application/json",
        ).json()
        assert len(response) == 13


class BulkSearchAPICPE(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("username", "e@mail.com", "secret")
        self.auth = f"Token {self.user.auth_token.key}"
        self.csrf_client = APIClient(enforce_csrf_checks=True)
        self.csrf_client.credentials(HTTP_AUTHORIZATION=self.auth)
        self.exclusive_cpes = [
            "cpe:/a:nginx:1.0.7",
            "cpe:/a:nginx:1.0.15",
            "cpe:/a:nginx:1.14.1",
            "cpe:/a:nginx:1.15.5",
            "cpe:/a:nginx:1.15.6",
        ]
        vuln = Vulnerability.objects.create(summary="test")
        for cpe in self.exclusive_cpes:
            ref = VulnerabilityReference.objects.create(reference_id=cpe)
            VulnerabilityRelatedReference.objects.create(reference=ref, vulnerability=vuln)
        second_vuln = Vulnerability.objects.create(summary="test-A")
        self.non_exclusive_cpes = [
            "cpe:/a:nginx:1.16.1",
            "cpe:/a:nginx:1.17.2",
            "cpe:/a:nginx:1.17.3",
            "cpe:/a:nginx:1.9.5",
            "cpe:/a:nginx:1.20.1",
            "cpe:/a:nginx:1.20.0",
            "cpe:/a:nginx:1.21.0",
        ]
        third_vuln = Vulnerability.objects.create(summary="test-B")
        for cpe in self.non_exclusive_cpes:
            ref = VulnerabilityReference.objects.create(reference_id=cpe)
            VulnerabilityRelatedReference.objects.create(reference=ref, vulnerability=second_vuln)
            VulnerabilityRelatedReference.objects.create(reference=ref, vulnerability=third_vuln)

    def test_api_response_with_with_exclusive_cpes_associated_with_two_vulnerabilities(self):
        request_body = {
            "cpes": self.exclusive_cpes,
        }
        response = self.csrf_client.post(
            "/api/cpes/bulk_search",
            data=json.dumps(request_body),
            content_type="application/json",
        ).json()
        assert len(response) == 1
        assert response[0]["summary"] == "test"
        references_in_vuln = response[0]["references"]
        cpes = [ref["reference_id"] for ref in references_in_vuln]
        assert set(cpes) == set(self.exclusive_cpes)

    def test_api_response_with_no_cpe_associated(self):
        request_body = {
            "cpes": ["cpe:/a:nginx:1.10.7"],
        }
        response = self.csrf_client.post(
            "/api/cpes/bulk_search",
            data=json.dumps(request_body),
            content_type="application/json",
        ).json()
        assert len(response) == 0

    def test_api_response_with_with_non_exclusive_cpes_associated_with_two_vulnerabilities(self):
        request_body = {
            "cpes": self.non_exclusive_cpes,
        }
        response = self.csrf_client.post(
            "/api/cpes/bulk_search",
            data=json.dumps(request_body),
            content_type="application/json",
        ).json()
        assert len(response) == 2

    def test_with_empty_list(self):
        request_body = {
            "cpes": [],
        }
        response = self.csrf_client.post(
            "/api/cpes/bulk_search",
            data=json.dumps(request_body),
            content_type="application/json",
        ).json()
        assert response == {"Error": "A non-empty 'cpes' list of CPEs is required."}

    def test_with_invalid_cpes(self):
        request_body = {"cpes": ["CVE-2022-2022"]}
        response = self.csrf_client.post(
            "/api/cpes/bulk_search",
            data=json.dumps(request_body),
            content_type="application/json",
        ).json()
        assert response == {"Error": "Invalid CPE: CVE-2022-2022"}
