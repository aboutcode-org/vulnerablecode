#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os
from urllib.parse import quote

from django.test import TestCase
from django.test import TransactionTestCase
from django.test.client import RequestFactory
from packageurl import PackageURL
from rest_framework import status
from rest_framework.test import APIClient

from vulnerabilities.api import PackageSerializer
from vulnerabilities.models import Alias
from vulnerabilities.models import ApiUser
from vulnerabilities.models import Package
from vulnerabilities.models import PackageRelatedVulnerability
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilityRelatedReference

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data")


def cleaned_response(response):
    """
    Return a cleaned response suitable for comparison in tests in particular:
    - sort lists with a stable order
    """
    cleaned_response = []
    response_copy = sorted(response, key=lambda x: x.get("purl", ""))
    for package_data in response_copy:
        package_data["unresolved_vulnerabilities"] = sorted(
            package_data["unresolved_vulnerabilities"], key=lambda x: x["vulnerability_id"]
        )
        for index, vulnerability in enumerate(package_data["unresolved_vulnerabilities"]):
            package_data["unresolved_vulnerabilities"][index]["references"] = sorted(
                vulnerability["references"], key=lambda x: (x["reference_id"], x["url"])
            )
            for index2, reference in enumerate(
                package_data["unresolved_vulnerabilities"][index]["references"]
            ):
                reference["scores"] = sorted(
                    reference["scores"], key=lambda x: (x["value"], x["scoring_system"])
                )
                package_data["unresolved_vulnerabilities"][index]["references"][index2][
                    "scores"
                ] = reference["scores"]

        package_data["resolved_vulnerabilities"] = sorted(
            package_data["resolved_vulnerabilities"], key=lambda x: x["vulnerability_id"]
        )
        for index, vulnerability in enumerate(package_data["resolved_vulnerabilities"]):
            package_data["resolved_vulnerabilities"][index]["references"] = sorted(
                vulnerability["references"], key=lambda x: (x["reference_id"], x["url"])
            )
            for index2, reference in enumerate(
                package_data["resolved_vulnerabilities"][index]["references"]
            ):
                reference["scores"] = sorted(
                    reference["scores"], key=lambda x: (x["value"], x["scoring_system"])
                )
                package_data["resolved_vulnerabilities"][index]["references"][index2][
                    "scores"
                ] = reference["scores"]

        cleaned_response.append(package_data)

    return cleaned_response


class TestDebianResponse(TransactionTestCase):
    def setUp(self):
        # create one non-debian package called "mimetex" to verify filtering
        Package.objects.create(name="mimetex", version="1.50-1.1", type="deb", namespace="ubuntu")
        self.user = ApiUser.objects.create_api_user(username="e@mail.com")
        self.auth = f"Token {self.user.auth_token.key}"
        self.client = APIClient(enforce_csrf_checks=True)
        self.client.credentials(HTTP_AUTHORIZATION=self.auth)

    def test_query_qualifier_filtering(self):

        # packages to check filtering with single/multiple and unordered qualifier filtering
        pk_multi_qf = Package.objects.create(
            name="vlc", version="1.50-1.1", type="deb", qualifiers={"foo": "bar", "tar": "ball"}
        )
        pk_single_qf = Package.objects.create(
            name="vlc", version="1.50-1.1", type="deb", qualifiers={"foo": "bar"}
        )

        # check filtering when qualifiers are not normalized
        test_purl = quote("pkg:deb/vlc@1.50-1.1?foo=bar&tar=ball")
        response = self.client.get(f"/api/packages/?purl={test_purl}", format="json").data

        self.assertEqual(2, response["count"])

        test_purl = quote("pkg:deb/vlc@1.50-1.1?tar=ball&foo=bar")
        response = self.client.get(f"/api/packages/?purl={test_purl}", format="json").data

        self.assertEqual(2, response["count"])

        # check filtering when there is intersection of qualifiers between packages
        test_purl = quote("pkg:deb/vlc@1.50-1.1?foo=bar")
        response = self.client.get(f"/api/packages/?purl={test_purl}", format="json").data

        self.assertEqual(2, response["count"])

    def test_query_by_name(self):
        response = self.client.get("/api/packages/?name=mimetex", format="json").data

        self.assertEqual(1, response["count"])

        first_result = response["results"][0]
        self.assertEqual("mimetex", first_result["name"])

        versions = {r["version"] for r in response["results"]}
        self.assertIn("1.50-1.1", versions)

        purls = {r["purl"] for r in response["results"]}
        self.assertIn("pkg:deb/ubuntu/mimetex@1.50-1.1", purls)

    def test_query_by_invalid_package_url(self):
        url = "/api/packages/?purl=invalid_purl"
        response = self.client.get(url, format="json")

        self.assertEqual(400, response.status_code)
        self.assertIn("error", response.data)
        error = response.data["error"]
        self.assertIn("invalid_purl", error)

    def test_query_by_package_url_without_namespace(self):
        url = "/api/packages/?purl=pkg:deb/mimetex@1.50-1.1"
        response = self.client.get(url, format="json").data

        self.assertEqual(1, response["count"])

        first_result = response["results"][0]
        self.assertEqual("mimetex", first_result["name"])

        purls = {r["purl"] for r in response["results"]}
        self.assertIn("pkg:deb/ubuntu/mimetex@1.50-1.1", purls)


class TestSerializers(TransactionTestCase):
    def setUp(self):
        Package.objects.create(
            name="mimetex",
            version="1.50-1.1",
            type="deb",
            namespace="ubuntu",
            qualifiers={"distro": "jessie"},
        )
        self.user = ApiUser.objects.create_api_user(username="e@mail.com")
        self.auth = f"Token {self.user.auth_token.key}"
        self.client = APIClient(enforce_csrf_checks=True)
        self.client.credentials(HTTP_AUTHORIZATION=self.auth)

    def test_package_serializer(self):
        pk = Package.objects.filter(name="mimetex")
        mock_request = RequestFactory().get("/api")
        response = PackageSerializer(pk, many=True, context={"request": mock_request}).data
        self.assertEqual(1, len(response))

        first_result = response[0]
        self.assertEqual("mimetex", first_result["name"])

        versions = {r["version"] for r in response}
        self.assertIn("1.50-1.1", versions)

        purls = {r["purl"] for r in response}
        self.assertIn("pkg:deb/ubuntu/mimetex@1.50-1.1?distro=jessie", purls)


class APITestCaseVulnerability(TransactionTestCase):
    def setUp(self):
        self.user = ApiUser.objects.create_api_user(username="e@mail.com")
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
                    "url": f"http://testserver/api/packages/{self.pkg2.id}",
                    "purl": "pkg:debian/flask@0.1.2",
                    "is_vulnerable": False,
                },
                {
                    "url": f"http://testserver/api/packages/{self.pkg1.id}",
                    "purl": "pkg:pypi/flask@0.1.2",
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
        self.user = ApiUser.objects.create_api_user(username="e@mail.com")
        self.auth = f"Token {self.user.auth_token.key}"
        self.csrf_client = APIClient(enforce_csrf_checks=True)
        self.csrf_client.credentials(HTTP_AUTHORIZATION=self.auth)
        vuln = Vulnerability.objects.create(
            summary="test-vuln",
        )
        self.vuln = vuln
        self.vulnerable_packages = []
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
        Alias.objects.create(alias="CVE-2019-1234", vulnerability=vuln1)
        Alias.objects.create(alias="GMS-1234-4321", vulnerability=vuln1)
        Alias.objects.create(alias="CVE-2029-1234", vulnerability=vuln)
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
                    "aliases": ["CVE-2019-1234", "GMS-1234-4321"],
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
                    "aliases": ["CVE-2029-1234"],
                },
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
                    "aliases": ["CVE-2029-1234"],
                }
            ],
            "fixing_vulnerabilities": [],
        }

    def test_api_with_all_vulnerable_packages(self):
        with self.assertNumQueries(4):
            # There are 4 queries:
            # 1. SAVEPOINT
            # 2. Authenticating user
            # 3. Get all vulnerable packages
            # 4. RELEASE SAVEPOINT
            response = self.csrf_client.get(f"/api/packages/all", format="json").data
            assert len(response) == 11
            assert response == [
                "pkg:generic/nginx/test@0",
                "pkg:generic/nginx/test@1",
                "pkg:generic/nginx/test@11",
                "pkg:generic/nginx/test@2",
                "pkg:generic/nginx/test@3",
                "pkg:generic/nginx/test@4",
                "pkg:generic/nginx/test@5",
                "pkg:generic/nginx/test@6",
                "pkg:generic/nginx/test@7",
                "pkg:generic/nginx/test@8",
                "pkg:generic/nginx/test@9",
            ]

    def test_api_with_ignorning_qualifiers(self):
        response = self.csrf_client.get(
            f"/api/packages/?purl=pkg:generic/nginx/test@9?foo=bar", format="json"
        ).data
        assert response["count"] == 1
        assert response["results"][0]["purl"] == "pkg:generic/nginx/test@9"


class CPEApi(TestCase):
    def setUp(self):
        self.user = ApiUser.objects.create_api_user(username="e@mail.com")
        self.auth = f"Token {self.user.auth_token.key}"
        self.csrf_client = APIClient(enforce_csrf_checks=True)
        self.csrf_client.credentials(HTTP_AUTHORIZATION=self.auth)
        self.vulnerability = Vulnerability.objects.create(summary="test")
        for i in range(0, 10):
            ref, _ = VulnerabilityReference.objects.get_or_create(
                reference_id=f"cpe:/a:nginx:{i}",
                url=f"https://nvd.nist.gov/vuln/search/results?adv_search=true&isCpeNameSearch=true&query=cpe:/a:nginx:{i}",
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
        self.user = ApiUser.objects.create_api_user(username="e@mail.com")
        self.auth = f"Token {self.user.auth_token.key}"
        self.csrf_client = APIClient(enforce_csrf_checks=True)
        self.csrf_client.credentials(HTTP_AUTHORIZATION=self.auth)
        self.vulnerability = Vulnerability.objects.create(summary="test")
        for i in range(0, 10):
            Alias.objects.create(alias=f"CVE-{i}", vulnerability=self.vulnerability)

    def test_api_status(self):
        response = self.csrf_client.get("/api/aliases/", format="json")
        self.assertEqual(status.HTTP_200_OK, response.status_code)

    def test_api_response(self):
        response = self.csrf_client.get("/api/aliases?alias=CVE-9", format="json").data
        self.assertEqual(response["count"], 1)


class BulkSearchAPIPackage(TestCase):
    def setUp(self):
        self.user = ApiUser.objects.create_api_user(username="e@mail.com")
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

        vulnerable_packages = [
            "pkg:nginx/nginx@1.0.15?foo=bar",
            "pkg:nginx/nginx@1.0.15?foo=baz",
        ]

        vuln = Vulnerability.objects.create(summary="test")

        for package in vulnerable_packages:
            purl = PackageURL.from_string(package)
            attrs = {k: v for k, v in purl.to_dict().items() if v}
            pkg = Package.objects.create(**attrs)
            PackageRelatedVulnerability.objects.create(package=pkg, vulnerability=vuln, fix=False)

    def test_bulk_api_response(self):
        request_body = {
            "purls": self.packages,
        }
        response = self.csrf_client.post(
            "/api/packages/bulk_search",
            data=json.dumps(request_body),
            content_type="application/json",
        ).json()
        assert len(response) == 13

    def test_bulk_api_response_with_ignoring_qualifiers(self):
        request_body = {"purls": ["pkg:nginx/nginx@1.0.15?qualifiers=dev"], "plain_purl": True}
        response = self.csrf_client.post(
            "/api/packages/bulk_search",
            data=json.dumps(request_body),
            content_type="application/json",
        ).json()
        assert len(response) == 1
        assert response[0]["purl"] == "pkg:nginx/nginx@1.0.15"

    def test_bulk_api_response_with_ignoring_subpath(self):
        request_body = {"purls": ["pkg:nginx/nginx@1.0.15#dev/subpath"], "plain_purl": True}
        response = self.csrf_client.post(
            "/api/packages/bulk_search",
            data=json.dumps(request_body),
            content_type="application/json",
        ).json()
        assert len(response) == 1
        assert response[0]["purl"] == "pkg:nginx/nginx@1.0.15"

    def test_bulk_api_with_purl_only_option(self):
        request_body = {
            "purls": ["pkg:nginx/nginx@1.0.15#dev/subpath"],
            "purl_only": True,
            "plain_purl": True,
        }
        response = self.csrf_client.post(
            "/api/packages/bulk_search",
            data=json.dumps(request_body),
            content_type="application/json",
        ).json()
        assert len(response) == 1
        assert response[0] == "pkg:nginx/nginx@1.0.15"

    def test_bulk_api_with_vuln_only_option(self):
        request_body = {
            "purls": ["pkg:nginx/nginx@1.0.15?foo=bar"],
            "vulnerabilities_only": True,
        }
        response = self.csrf_client.post(
            "/api/packages/bulk_search",
            data=json.dumps(request_body),
            content_type="application/json",
        ).json()
        assert len(response) == 1
        assert response[0]["affected_by_vulnerabilities"][0]["summary"] == "test"


class BulkSearchAPICPE(TestCase):
    def setUp(self):
        self.user = ApiUser.objects.create_api_user(username="e@mail.com")
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
            ref = VulnerabilityReference.objects.create(
                reference_id=cpe,
                url=f"https://nvd.nist.gov/vuln/search/results?adv_search=true&isCpeNameSearch=true&query={cpe}",
            )
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
            ref = VulnerabilityReference.objects.create(
                reference_id=cpe,
                url=f"https://nvd.nist.gov/vuln/search/results?adv_search=true&isCpeNameSearch=true&query={cpe}",
            )
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
