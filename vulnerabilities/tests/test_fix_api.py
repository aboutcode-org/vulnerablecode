# Copyright (c) nexB Inc. and others. All rights reserved.
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
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

from django.test import TestCase
from rest_framework import status

from vulnerabilities.models import Package
from vulnerabilities.models import Vulnerability


class APITestCaseVulnerability(TestCase):
    def setUp(self):
        for i in range(0, 10):
            Vulnerability.objects.create(
                summary=str(i),
            )
        self.vulnerability = Vulnerability.objects.create(summary="test")

    def test_api_status(self):
        response = self.client.get("/api/vulnerabilities/", format="json")
        self.assertEqual(status.HTTP_200_OK, response.status_code)

    def test_api_response(self):
        response = self.client.get("/api/vulnerabilities/", format="json").data
        self.assertEqual(response["count"], 11)

    def test_api_with_single_vulnerability(self):
        response = self.client.get(
            f"/api/vulnerabilities/{self.vulnerability.id}", format="json"
        ).data
        assert response["summary"] == "test"


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
        assert response["name"] == "test-vulnDB"
        assert response["version"] == "1.0"
        assert response["type"] == "generic"
