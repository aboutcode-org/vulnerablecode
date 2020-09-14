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
from random import choices
from unittest.mock import MagicMock
from urllib.parse import quote

from django.test import TestCase
from django.test.client import RequestFactory

from vulnerabilities.api import PackageSerializer
from vulnerabilities.models import Package


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/")


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
