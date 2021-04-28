#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import os
from collections import OrderedDict
from random import choices
from unittest.mock import MagicMock
from urllib.parse import quote

from django.test import TestCase
from django.test.client import RequestFactory

from vulnerabilities.api import PackageSerializer
from vulnerabilities.models import Package
from rest_framework.test import APIRequestFactory
from rest_framework.test import APIClient


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/")


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


class TestDebianResponse(TestCase):
    fixtures = ["debian.json"]

    @classmethod
    def setUpTestData(cls):
        # create one non-debian package called "mimetex" to verify filtering
        Package.objects.create(name="mimetex", version="1.50-1.1", type="deb", namespace="ubuntu")

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

        self.assertEqual(1, response["count"])
        self.assertEqual(pk_multi_qf.qualifiers, response["results"][0]["qualifiers"])

        test_purl = quote("pkg:deb/vlc@1.50-1.1?tar=ball&foo=bar")
        response = self.client.get(f"/api/packages/?purl={test_purl}", format="json").data

        self.assertEqual(1, response["count"])
        self.assertEqual(pk_multi_qf.qualifiers, response["results"][0]["qualifiers"])

        # check filtering when there is intersection of qualifiers between packages
        test_purl = quote("pkg:deb/vlc@1.50-1.1?foo=bar")
        response = self.client.get(f"/api/packages/?purl={test_purl}", format="json").data

        self.assertEqual(1, response["count"])

    def test_query_by_name(self):
        response = self.client.get("/api/packages/?name=mimetex", format="json").data

        self.assertEqual(3, response["count"])

        first_result = response["results"][0]
        self.assertEqual("mimetex", first_result["name"])

        versions = {r["version"] for r in response["results"]}
        self.assertIn("1.50-1.1", versions)
        self.assertIn("1.74-1", versions)

        purls = {r["purl"] for r in response["results"]}
        self.assertIn("pkg:deb/debian/mimetex@1.50-1.1?distro=jessie", purls)
        self.assertIn("pkg:deb/debian/mimetex@1.74-1?distro=jessie", purls)

    def test_query_by_invalid_package_url(self):
        url = "/api/packages/?purl=invalid_purl"
        response = self.client.get(url, format="json")

        self.assertEqual(400, response.status_code)
        self.assertIn("error", response.data)
        error = response.data["error"]
        self.assertIn("invalid_purl", error)

    def test_query_by_package_url(self):
        url = "/api/packages/?purl=pkg:deb/debian/mimetex@1.50-1.1?distro=jessie"
        response = self.client.get(url, format="json").data

        self.assertEqual(1, response["count"])

        first_result = response["results"][0]
        self.assertEqual("mimetex", first_result["name"])

        versions = {r["version"] for r in response["results"]}
        self.assertIn("1.50-1.1", versions)
        self.assertNotIn("1.74-1", versions)

    def test_query_by_package_url_without_namespace(self):
        url = "/api/packages/?purl=pkg:deb/mimetex@1.50-1.1"
        response = self.client.get(url, format="json").data

        self.assertEqual(2, response["count"])

        first_result = response["results"][0]
        self.assertEqual("mimetex", first_result["name"])

        purls = {r["purl"] for r in response["results"]}
        self.assertIn("pkg:deb/debian/mimetex@1.50-1.1?distro=jessie", purls)
        self.assertIn("pkg:deb/ubuntu/mimetex@1.50-1.1", purls)


class APIResponseRelations(TestCase):
    fixtures = ["openssl.json"]

    def test_vulnerability_package_relations(self):

        test_pkgs = choices(Package.objects.all(), k=5)
        for test_pkg in test_pkgs:

            pkg_response = self.client.get(f"/api/packages/{test_pkg.id}/", format="json").data
            resolved_vulns = {
                vuln["vulnerability_id"] for vuln in pkg_response["resolved_vulnerabilities"]
            }
            unresolved_vulns = {
                vuln["vulnerability_id"] for vuln in pkg_response["unresolved_vulnerabilities"]
            }

            for vuln in resolved_vulns:
                vuln_resp = self.client.get(
                    f"/api/vulnerabilities/?vulnerability_id={vuln}", format="json"
                ).data

                if not vuln_resp["results"]:
                    continue

                resolved_purls = {
                    package["purl"] for package in vuln_resp["results"][0]["resolved_packages"]
                }
                self.assertIn(test_pkg.package_url, resolved_purls)

            for vuln in unresolved_vulns:
                vuln_resp = self.client.get(
                    f"/api/vulnerabilities/?vulnerability_id={vuln}", format="json"
                ).data

                if not vuln_resp["results"]:
                    continue

                unresolved_purls = {
                    package["purl"] for package in vuln_resp["results"][0]["unresolved_packages"]
                }
                self.assertIn(test_pkg.package_url, unresolved_purls)


class TestSerializers(TestCase):
    fixtures = ["debian.json"]

    def test_package_serializer(self):
        pk = Package.objects.filter(name="mimetex")
        mock_request = RequestFactory().get("/api")
        response = PackageSerializer(pk, many=True, context={"request": mock_request}).data
        self.assertEqual(2, len(response))

        first_result = response[0]
        self.assertEqual("mimetex", first_result["name"])

        versions = {r["version"] for r in response}
        self.assertIn("1.50-1.1", versions)
        self.assertIn("1.74-1", versions)

        purls = {r["purl"] for r in response}
        self.assertIn("pkg:deb/debian/mimetex@1.50-1.1?distro=jessie", purls)
        self.assertIn("pkg:deb/debian/mimetex@1.74-1?distro=jessie", purls)


class TestBulkAPIResponse(TestCase):
    fixtures = ["github.json"]

    def test_bulk_packages_api(self):
        request_body = {
            "purls": [
                "pkg:deb/debian/doesnotexist@0.9.7-10?distro=jessie",
                "pkg:maven/com.datadoghq/datadog-api-client@1.0.0-beta.7",
            ]
        }
        response = self.client.post(
            "/api/packages/bulk_search/",
            data=request_body,
            content_type="application/json",
        ).json()

        expected_response = [
            {
                "purl": "pkg:deb/debian/doesnotexist@0.9.7-10?distro=jessie",
                "name": "doesnotexist",
                "namespace": "debian",
                "qualifiers": {"distro": "jessie"},
                "resolved_vulnerabilities": [],
                "subpath": None,
                "type": "deb",
                "unresolved_vulnerabilities": [],
                "version": "0.9.7-10",
            },
            {
                "name": "datadog-api-client",
                "namespace": "com.datadoghq",
                "purl": "pkg:maven/com.datadoghq/datadog-api-client@1.0.0-beta.7",
                "qualifiers": {},
                "resolved_vulnerabilities": [],
                "subpath": "",
                "type": "maven",
                "unresolved_vulnerabilities": [
                    {
                        "references": [
                            {
                                "reference_id": "",
                                "scores": [],
                                "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-21331",
                            },
                            {
                                "reference_id": "GHSA-2cxf-6567-7pp6",
                                "scores": [{"scoring_system": "cvssv3.1_qr", "value": "LOW"}],
                                "url": "https://github.com/DataDog/datadog-api-client-java/security/advisories/GHSA-2cxf-6567-7pp6",
                            },
                            {
                                "reference_id": "GHSA-2cxf-6567-7pp6",
                                "scores": [],
                                "url": "https://github.com/advisories/GHSA-2cxf-6567-7pp6",
                            },
                        ],
                        "url": "http://testserver/api/vulnerabilities/60",
                        "vulnerability_id": "CVE-2021-21331",
                    }
                ],
                "url": "http://testserver/api/packages/3467",
                "version": "1.0.0-beta.7",
            },
        ]
        assert cleaned_response(expected_response) == cleaned_response(response)

    def test_invalid_request_bulk_packages(self):
        error_response = {
            "Error": "A non-empty 'purls' list of package URLs is required."  # nopep8
        }
        invalid_key_request_data = {"pkg": []}
        response = self.client.post(
            "/api/packages/bulk_search/",
            data=invalid_key_request_data,
            content_type="application/json",
        ).data
        assert response == error_response

        valid_key_invalid_datatype_request_data = {"packages": {}}
        response = self.client.post(
            "/api/packages/bulk_search/",
            data=valid_key_invalid_datatype_request_data,
            content_type="application/json",
        ).data

        assert response == error_response

        invalid_purl_request_data = {
            "purls": [
                "pkg:deb/debian/librsync@0.9.7-10?distro=jessie",
                "pg:deb/debian/mimetex@1.50-1.1?distro=jessie",
            ]
        }
        response = self.client.post(
            "/api/packages/bulk_search/",
            data=invalid_purl_request_data,
            content_type="application/json",
        ).data
        purl_error_respones = {
            "Error": "Invalid Package URL: pg:deb/debian/mimetex@1.50-1.1?distro=jessie"
        }
        assert response == purl_error_respones
