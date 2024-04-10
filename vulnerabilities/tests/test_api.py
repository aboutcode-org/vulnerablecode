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
from collections import OrderedDict
from datetime import datetime
from urllib.parse import quote

from django.test import TestCase
from django.test import TransactionTestCase
from django.test.client import RequestFactory
from packageurl import PackageURL
from rest_framework import status
from rest_framework.test import APIClient

from vulnerabilities.api import MinimalPackageSerializer
from vulnerabilities.api import PackageSerializer
from vulnerabilities.models import Advisory
from vulnerabilities.models import Alias
from vulnerabilities.models import ApiUser
from vulnerabilities.models import Package
from vulnerabilities.models import PackageRelatedVulnerability
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilityRelatedReference
from vulnerabilities.models import Weakness

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
        self.alias = Alias.objects.create(alias="CORE-2010-0121", vulnerability=self.vulnerability)
        self.pkg1 = Package.objects.create(name="flask", type="pypi", version="0.1.2")
        self.pkg2 = Package.objects.create(name="flask", type="deb", version="0.1.2")
        for pkg in [self.pkg1, self.pkg2]:
            PackageRelatedVulnerability.objects.create(
                package=pkg, vulnerability=self.vulnerability, fix=True
            )
        self.weaknesses = Weakness.objects.create(cwe_id=119)
        self.advisory = Advisory.objects.create(
            unique_content_id="6b7d417a552b19f26a5c2267ba7876c2",
            aliases=["CORE-2010-0121"],
            summary="Vulnerabilities with Windows 8.3 filename pseudonyms",
            affected_packages=[],
            url="https://nginx.org/en/security_advisories.html",
            date_collected=datetime.now(),
            created_by="vulnerabilities.importers.nginx.NginxImporter",
        )
        self.weaknesses.vulnerabilities.add(self.vulnerability)
        self.invalid_weaknesses = Weakness.objects.create(
            cwe_id=10000
        )  # cwe not present in weaknesses_db
        self.invalid_weaknesses.vulnerabilities.add(self.vulnerability)

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
            "aliases": [OrderedDict([("alias", "CORE-2010-0121")])],
            "resource_url": f"http://testserver/vulnerabilities/{self.vulnerability.vulnerability_id}",
            "fixed_packages": [
                {
                    "url": f"http://testserver/api/packages/{self.pkg2.id}",
                    "purl": "pkg:deb/flask@0.1.2",
                    "is_vulnerable": False,
                    "affected_by_vulnerabilities": [],
                    "resource_url": f"http://testserver/packages/{self.pkg2.purl}",
                },
                {
                    "url": f"http://testserver/api/packages/{self.pkg1.id}",
                    "purl": "pkg:pypi/flask@0.1.2",
                    "is_vulnerable": False,
                    "affected_by_vulnerabilities": [],
                    "resource_url": f"http://testserver/packages/{self.pkg1.purl}",
                },
            ],
            "affected_packages": [],
            "references": [],
            "weaknesses": [
                {
                    "cwe_id": 119,
                    "name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
                    "description": "The software performs operations on a memory buffer, but it can read from or write to a memory location that is outside of the intended boundary of the buffer.",
                },
            ],
            "advisory": [
                {
                    "unique_content_id": "6b7d417a552b19f26a5c2267ba7876c2",
                    "url": "https://nginx.org/en/security_advisories.html",
                    "summary": "Vulnerabilities with Windows 8.3 filename pseudonyms",
                }
            ],
        }

    def test_api_with_single_vulnerability_with_filters(self):
        response = self.csrf_client.get(
            f"/api/vulnerabilities/{self.vulnerability.id}?type=pypi", format="json"
        ).data
        assert response == {
            "url": f"http://testserver/api/vulnerabilities/{self.vulnerability.id}",
            "vulnerability_id": self.vulnerability.vulnerability_id,
            "summary": "test",
            "aliases": [OrderedDict([("alias", "CORE-2010-0121")])],
            "resource_url": f"http://testserver/vulnerabilities/{self.vulnerability.vulnerability_id}",
            "fixed_packages": [
                {
                    "url": f"http://testserver/api/packages/{self.pkg1.id}",
                    "purl": "pkg:pypi/flask@0.1.2",
                    "is_vulnerable": False,
                    "resource_url": f"http://testserver/packages/{self.pkg1.purl}",
                    "affected_by_vulnerabilities": [],
                },
            ],
            "affected_packages": [],
            "references": [],
            "weaknesses": [
                {
                    "cwe_id": 119,
                    "name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
                    "description": "The software performs operations on a memory buffer, but it can read from or write to a memory location that is outside of the intended boundary of the buffer.",
                },
            ],
            "advisory": [
                {
                    "unique_content_id": "6b7d417a552b19f26a5c2267ba7876c2",
                    "url": "https://nginx.org/en/security_advisories.html",
                    "summary": "Vulnerabilities with Windows 8.3 filename pseudonyms",
                }
            ],
        }


class APITestCasePackage(TestCase):
    def setUp(self):
        self.user = ApiUser.objects.create_api_user(username="e@mail.com")
        self.auth = f"Token {self.user.auth_token.key}"
        self.csrf_client = APIClient(enforce_csrf_checks=True)
        self.csrf_client.credentials(HTTP_AUTHORIZATION=self.auth)

        # searched-for pkg
        self.package_maven_jackson_databind_2_13_1 = Package.objects.create(
            type="maven",
            namespace="com.fasterxml.jackson.core",
            name="jackson-databind",
            version="2.13.1",
            qualifiers={},
            subpath="",
        )

        # searched-for pkg's vuln
        self.vuln_VCID_2nyb_8rwu_aaag = Vulnerability.objects.create(
            summary="This is VCID-2nyb-8rwu-aaag",
            vulnerability_id="VCID-2nyb-8rwu-aaag",
        )

        # pkg-vuln affect relationship
        PackageRelatedVulnerability.objects.create(
            package=self.package_maven_jackson_databind_2_13_1,
            vulnerability=self.vuln_VCID_2nyb_8rwu_aaag,
            fix=False,
        )

        # vuln aliases
        Alias.objects.create(alias="CVE-2020-36518", vulnerability=self.vuln_VCID_2nyb_8rwu_aaag)
        Alias.objects.create(
            alias="GHSA-57j2-w4cx-62h2", vulnerability=self.vuln_VCID_2nyb_8rwu_aaag
        )

        # pkg (1 of 2 -- this is a lesser version and will be omitted from the API) that fixes searched-for pkg's vuln
        self.package_maven_jackson_databind_2_12_6_1 = Package.objects.create(
            type="maven",
            namespace="com.fasterxml.jackson.core",
            name="jackson-databind",
            version="2.12.6.1",
            qualifiers={},
            subpath="",
        )

        # pkg-vuln fix relationship
        PackageRelatedVulnerability.objects.create(
            package=self.package_maven_jackson_databind_2_12_6_1,
            vulnerability=self.vuln_VCID_2nyb_8rwu_aaag,
            fix=True,
        )

        # fixed by pkg own vuln
        self.vuln_VCID_gqhw_ngh8_aaap = Vulnerability.objects.create(
            summary="This is VCID-gqhw-ngh8-aaap",
            vulnerability_id="VCID-gqhw-ngh8-aaap",
        )

        # pkg-vuln affect relationship
        PackageRelatedVulnerability.objects.create(
            package=self.package_maven_jackson_databind_2_12_6_1,
            vulnerability=self.vuln_VCID_gqhw_ngh8_aaap,
            fix=False,
        )

        # pkg (2 of 2 -- this is a greater version) that fixes searched-for pkg's vuln
        self.package_maven_jackson_databind_2_13_2 = Package.objects.create(
            type="maven",
            namespace="com.fasterxml.jackson.core",
            name="jackson-databind",
            version="2.13.2",
            qualifiers={},
            subpath="",
        )

        # pkg-vuln fix relationship
        PackageRelatedVulnerability.objects.create(
            package=self.package_maven_jackson_databind_2_13_2,
            vulnerability=self.vuln_VCID_2nyb_8rwu_aaag,
            fix=True,
        )

        # pkg-vuln affect relationship
        PackageRelatedVulnerability.objects.create(
            package=self.package_maven_jackson_databind_2_13_2,
            vulnerability=self.vuln_VCID_gqhw_ngh8_aaap,
            fix=False,
        )

        # This is the vuln fixed by the searched-for pkg -- and by a lesser version (created below), which WILL be included in the API
        self.vuln_VCID_ftmk_wbwx_aaar = Vulnerability.objects.create(
            summary="This is VCID-ftmk-wbwx-aaar",
            vulnerability_id="VCID-ftmk-wbwx-aaar",
        )

        # searched-for pkg-vuln fix relationship
        PackageRelatedVulnerability.objects.create(
            package=self.package_maven_jackson_databind_2_13_1,
            vulnerability=self.vuln_VCID_ftmk_wbwx_aaar,
            fix=True,
        )

        # lesser-version pkg that also fixes the vuln fixed by the searched-for pkg
        self.package_maven_jackson_databind_2_12_6 = Package.objects.create(
            type="maven",
            namespace="com.fasterxml.jackson.core",
            name="jackson-databind",
            version="2.12.6",
            qualifiers={},
            subpath="",
        )

        # lesser-version pkg-vuln fix relationship
        PackageRelatedVulnerability.objects.create(
            package=self.package_maven_jackson_databind_2_12_6,
            vulnerability=self.vuln_VCID_ftmk_wbwx_aaar,
            fix=True,
        )

        # aliases for vuln fixed by searched-for pkg
        Alias.objects.create(alias="CVE-2021-46877", vulnerability=self.vuln_VCID_ftmk_wbwx_aaar)
        Alias.objects.create(
            alias="GHSA-3x8x-79m2-3w2w", vulnerability=self.vuln_VCID_ftmk_wbwx_aaar
        )

        # This addresses both next and latest non-vulnerable pkg
        self.package_maven_jackson_databind_2_14_0_rc1 = Package.objects.create(
            type="maven",
            namespace="com.fasterxml.jackson.core",
            name="jackson-databind",
            version="2.14.0-rc1",
            qualifiers={},
            subpath="",
        )

    def test_api_with_package_with_no_vulnerabilities(self):
        affected_vulnerabilities = []
        vuln = {
            "foo": "bar",
        }

        package_with_no_vulnerabilities = MinimalPackageSerializer.get_vulnerability(
            self,
            vuln,
        )

        assert package_with_no_vulnerabilities is None

    def test_api_with_lesser_and_greater_fixed_by_packages(self):
        response = self.csrf_client.get(
            f"/api/packages/{self.package_maven_jackson_databind_2_13_1.id}", format="json"
        ).data

        expected_response = {
            "url": f"http://testserver/api/packages/{self.package_maven_jackson_databind_2_13_1.id}",
            "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1",
            "type": "maven",
            "namespace": "com.fasterxml.jackson.core",
            "name": "jackson-databind",
            "version": "2.13.1",
            "qualifiers": {},
            "subpath": "",
            "next_non_vulnerable_version": "2.14.0-rc1",
            "latest_non_vulnerable_version": "2.14.0-rc1",
            "affected_by_vulnerabilities": [
                OrderedDict(
                    [
                        (
                            "url",
                            f"http://testserver/api/vulnerabilities/{self.vuln_VCID_2nyb_8rwu_aaag.id}",
                        ),
                        ("vulnerability_id", "VCID-2nyb-8rwu-aaag"),
                        ("summary", "This is VCID-2nyb-8rwu-aaag"),
                        ("references", []),
                        (
                            "fixed_packages",
                            [
                                OrderedDict(
                                    [
                                        (
                                            "url",
                                            f"http://testserver/api/packages/{self.package_maven_jackson_databind_2_13_2.id}",
                                        ),
                                        (
                                            "purl",
                                            "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2",
                                        ),
                                        ("is_vulnerable", True),
                                        (
                                            "affected_by_vulnerabilities",
                                            [{"vulnerability": "VCID-gqhw-ngh8-aaap"}],
                                        ),
                                        (
                                            "resource_url",
                                            "http://testserver/packages/pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2",
                                        ),
                                    ]
                                )
                            ],
                        ),
                        ("aliases", ["CVE-2020-36518", "GHSA-57j2-w4cx-62h2"]),
                        ("resource_url", "http://testserver/vulnerabilities/VCID-2nyb-8rwu-aaag"),
                    ]
                )
            ],
            "fixing_vulnerabilities": [
                OrderedDict(
                    [
                        (
                            "url",
                            f"http://testserver/api/vulnerabilities/{self.vuln_VCID_ftmk_wbwx_aaar.id}",
                        ),
                        ("vulnerability_id", "VCID-ftmk-wbwx-aaar"),
                        ("summary", "This is VCID-ftmk-wbwx-aaar"),
                        ("references", []),
                        (
                            "fixed_packages",
                            [
                                OrderedDict(
                                    [
                                        (
                                            "url",
                                            f"http://testserver/api/packages/{self.package_maven_jackson_databind_2_12_6.id}",
                                        ),
                                        (
                                            "purl",
                                            "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.12.6",
                                        ),
                                        ("is_vulnerable", False),
                                        ("affected_by_vulnerabilities", []),
                                        (
                                            "resource_url",
                                            "http://testserver/packages/pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.12.6",
                                        ),
                                    ]
                                ),
                                OrderedDict(
                                    [
                                        (
                                            "url",
                                            f"http://testserver/api/packages/{self.package_maven_jackson_databind_2_13_1.id}",
                                        ),
                                        (
                                            "purl",
                                            "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1",
                                        ),
                                        ("is_vulnerable", True),
                                        (
                                            "affected_by_vulnerabilities",
                                            [{"vulnerability": "VCID-2nyb-8rwu-aaag"}],
                                        ),
                                        (
                                            "resource_url",
                                            "http://testserver/packages/pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1",
                                        ),
                                    ]
                                ),
                            ],
                        ),
                        ("aliases", ["CVE-2021-46877", "GHSA-3x8x-79m2-3w2w"]),
                        ("resource_url", "http://testserver/vulnerabilities/VCID-ftmk-wbwx-aaar"),
                    ]
                )
            ],
            "resource_url": "http://testserver/packages/pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1",
        }

        assert response == expected_response

    def test_is_vulnerable_attribute(self):
        self.assertTrue(self.package_maven_jackson_databind_2_13_1.is_vulnerable)

    def test_api_status(self):
        response = self.csrf_client.get("/api/packages/", format="json")
        self.assertEqual(status.HTTP_200_OK, response.status_code)

    def test_api_response(self):
        response = self.csrf_client.get("/api/packages/", format="json").data
        self.assertEqual(response["count"], 5)

    def test_api_with_namespace_filter(self):
        response = self.csrf_client.get(
            "/api/packages/?namespace=com.fasterxml.jackson.core", format="json"
        ).data
        self.assertEqual(response["count"], 5)

    def test_api_with_wrong_namespace_filter(self):
        response = self.csrf_client.get("/api/packages/?namespace=foo-bar", format="json").data
        self.assertEqual(response["count"], 0)

    def test_api_with_all_vulnerable_packages(self):
        with self.assertNumQueries(4):
            # There are 4 queries:
            # 1. SAVEPOINT
            # 2. Authenticating user
            # 3. Get all vulnerable packages
            # 4. RELEASE SAVEPOINT
            response = self.csrf_client.get(f"/api/packages/all", format="json").data

            assert len(response) == 3
            assert response == [
                "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.12.6.1",
                "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1",
                "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2",
            ]

    def test_api_with_ignorning_qualifiers(self):
        response = self.csrf_client.get(
            f"/api/packages/?purl=pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.0-rc1?foo=bar",
            format="json",
        ).data
        assert response["count"] == 1
        assert (
            response["results"][0]["purl"]
            == "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.0-rc1"
        )


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
            PackageRelatedVulnerability.objects.create(package=pkg, vulnerability=vuln)

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

    def test_bulk_api_without_purls_list(self):
        request_body = {
            "purls": None,
        }
        response = self.csrf_client.post(
            "/api/packages/bulk_search",
            data=json.dumps(request_body),
            content_type="application/json",
        ).json()

        expected = {
            "error": {"purls": ["This field may not be null."]},
            "message": "A non-empty 'purls' list of PURLs is required.",
        }

        self.assertEqual(response, expected)

    def test_bulk_api_without_purls_empty_list(self):
        request_body = {
            "purls": [],
        }
        response = self.csrf_client.post(
            "/api/packages/bulk_search",
            data=json.dumps(request_body),
            content_type="application/json",
        ).json()

        expected = {
            "error": {"purls": ["This list may not be empty."]},
            "message": "A non-empty 'purls' list of PURLs is required.",
        }

        self.assertEqual(response, expected)

    def test_bulk_api_with_empty_request_body(self):
        request_body = {}
        response = self.csrf_client.post(
            "/api/packages/bulk_search",
            data=json.dumps(request_body),
            content_type="application/json",
        ).json()

        expected = {
            "error": {"purls": ["This field is required."]},
            "message": "A non-empty 'purls' list of PURLs is required.",
        }

        self.assertEqual(response, expected)


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


class TesBanUserAgent(TestCase):
    def test_ban_request_with_bytedance_user_agent(self):
        response = self.client.get(f"/api/packages", format="json", HTTP_USER_AGENT="bytedance")
        assert 404 == response.status_code


class TestLookup(TestCase):
    def setUp(self):
        Package.objects.create(
            type="pypi", namespace="", name="microweber/microweber", version="1.2"
        )
        self.user = ApiUser.objects.create_api_user(username="e@mail.com")
        self.auth = f"Token {self.user.auth_token.key}"
        self.csrf_client = APIClient(enforce_csrf_checks=True)
        self.csrf_client.credentials(HTTP_AUTHORIZATION=self.auth)

    def test_lookup_endpoint_failure(self):
        request_body = {"purl": None}
        response = self.csrf_client.post(
            "/api/packages/lookup",
            data=json.dumps(request_body),
            content_type="application/json",
        ).json()

        expected = {
            "error": {"purl": ["This field may not be null."]},
            "message": "A 'purl' is required.",
        }

        self.assertEqual(response, expected)

    def test_lookup_endpoint(self):
        request_body = {"purl": "pkg:pypi/microweber/microweber@1.2"}
        response = self.csrf_client.post(
            "/api/packages/lookup",
            data=json.dumps(request_body),
            content_type="application/json",
        ).json()
        assert len(response) == 1
        assert response[0]["purl"] == "pkg:pypi/microweber/microweber@1.2"

    def test_bulk_lookup_endpoint(self):
        request_body = {
            "purls": [
                "pkg:pypi/microweber/microweber@1.2?foo=bar",
                "pkg:pypi/microweber/microweber@1.2",
                "pkg:pypi/foo/bar@1.0",
            ],
        }
        response = self.csrf_client.post(
            "/api/packages/bulk_lookup",
            data=json.dumps(request_body),
            content_type="application/json",
        ).json()
        assert len(response) == 1

    def test_bulk_lookup_endpoint_failure(self):
        request_body = {"purls": None}
        response = self.csrf_client.post(
            "/api/packages/bulk_lookup",
            data=json.dumps(request_body),
            content_type="application/json",
        ).json()

        expected = {
            "error": {"purls": ["This field may not be null."]},
            "message": "A non-empty 'purls' list of PURLs is required.",
        }

        self.assertEqual(response, expected)
