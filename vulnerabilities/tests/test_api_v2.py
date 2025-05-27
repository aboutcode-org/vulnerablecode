#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db.models import Prefetch
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework.test import APITestCase

from vulnerabilities.api_v2 import PackageV2Serializer
from vulnerabilities.api_v2 import VulnerabilityListSerializer
from vulnerabilities.models import Alias
from vulnerabilities.models import ApiUser
from vulnerabilities.models import Package
from vulnerabilities.models import PipelineRun
from vulnerabilities.models import PipelineSchedule
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import Weakness


class VulnerabilityV2ViewSetTest(APITestCase):
    def setUp(self):
        # Create vulnerabilities
        self.vuln1 = Vulnerability.objects.create(
            vulnerability_id="VCID-1234", summary="Test vulnerability 1"
        )
        self.vuln2 = Vulnerability.objects.create(
            vulnerability_id="VCID-5678", summary="Test vulnerability 2"
        )

        # Create aliases
        Alias.objects.create(alias="CVE-2021-1234", vulnerability=self.vuln1)
        Alias.objects.create(alias="CVE-2021-5678", vulnerability=self.vuln2)

        # Create weaknesses
        self.weakness1 = Weakness.objects.create(cwe_id=79)
        self.weakness1.vulnerabilities.add(self.vuln1)

        self.weakness2 = Weakness.objects.create(cwe_id=89)
        self.weakness2.vulnerabilities.add(self.vuln2)

        # Create references
        self.reference1 = VulnerabilityReference.objects.create(
            url="https://example.com/ref1", reference_type="advisory", reference_id="REF-1"
        )
        self.reference1.vulnerabilities.add(self.vuln1)

        self.reference2 = VulnerabilityReference.objects.create(
            url="https://example.com/ref2", reference_type="exploit", reference_id="REF-2"
        )
        self.reference2.vulnerabilities.add(self.vuln2)

        self.user = ApiUser.objects.create_api_user(username="e@mail.com")
        self.auth = f"Token {self.user.auth_token.key}"
        self.client = APIClient(enforce_csrf_checks=True)
        self.client.credentials(HTTP_AUTHORIZATION=self.auth)

    def test_list_vulnerabilities(self):
        """
        Test listing vulnerabilities without filters.
        Should return a paginated response with vulnerabilities dictionary.
        """
        url = reverse("vulnerability-v2-list")
        response = self.client.get(url, format="json")
        with self.assertNumQueries(5):
            response = self.client.get(url, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertIn("vulnerabilities", response.data["results"])
        self.assertEqual(len(response.data["results"]["vulnerabilities"]), 2)
        self.assertIn("VCID-1234", response.data["results"]["vulnerabilities"])
        self.assertIn("VCID-5678", response.data["results"]["vulnerabilities"])
        self.assertTrue("url" in response.data["results"]["vulnerabilities"]["VCID-1234"])

    def test_retrieve_vulnerability_detail(self):
        """
        Test retrieving vulnerability details by vulnerability_id.
        """
        url = reverse("vulnerability-v2-detail", kwargs={"vulnerability_id": "VCID-1234"})
        with self.assertNumQueries(8):
            response = self.client.get(url, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["vulnerability_id"], "VCID-1234")
        self.assertEqual(response.data["summary"], "Test vulnerability 1")
        self.assertEqual(response.data["aliases"], ["CVE-2021-1234"])
        self.assertEqual(len(response.data["weaknesses"]), 1)
        self.assertEqual(len(response.data["references"]), 1)

    def test_filter_vulnerability_by_vulnerability_id(self):
        """
        Test filtering vulnerabilities by vulnerability_id.
        """
        url = reverse("vulnerability-v2-list")
        with self.assertNumQueries(4):
            response = self.client.get(url, {"vulnerability_id": "VCID-1234"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["vulnerability_id"], "VCID-1234")

    def test_filter_vulnerability_by_alias(self):
        """
        Test filtering vulnerabilities by alias.
        """
        url = reverse("vulnerability-v2-list")
        with self.assertNumQueries(5):
            response = self.client.get(url, {"alias": "CVE-2021-5678"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertIn("vulnerabilities", response.data["results"])
        self.assertEqual(
            response.data["results"]["vulnerabilities"]["VCID-5678"]["vulnerability_id"],
            "VCID-5678",
        )

    def test_filter_vulnerabilities_multiple_ids(self):
        """
        Test filtering vulnerabilities by multiple vulnerability_ids.
        """
        url = reverse("vulnerability-v2-list")
        with self.assertNumQueries(5):
            response = self.client.get(
                url, {"vulnerability_id": ["VCID-1234", "VCID-5678"]}, format="json"
            )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]["vulnerabilities"]), 2)

    def test_filter_vulnerabilities_multiple_aliases(self):
        """
        Test filtering vulnerabilities by multiple aliases.
        """
        url = reverse("vulnerability-v2-list")
        with self.assertNumQueries(5):
            response = self.client.get(
                url, {"alias": ["CVE-2021-1234", "CVE-2021-5678"]}, format="json"
            )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]["vulnerabilities"]), 2)

    def test_invalid_vulnerability_id(self):
        """
        Test retrieving a vulnerability with an invalid vulnerability_id.
        Should return 404 Not Found.
        """
        url = reverse("vulnerability-v2-detail", kwargs={"vulnerability_id": "VCID-9999"})
        with self.assertNumQueries(5):
            response = self.client.get(url, format="json")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_get_url_in_serializer(self):
        """
        Test that the serializer correctly includes the URL field.
        """
        vulnerability = Vulnerability.objects.get(vulnerability_id="VCID-1234")
        serializer = VulnerabilityListSerializer(vulnerability, context={"request": None})
        self.assertIn("url", serializer.data)
        self.assertEqual(serializer.data["vulnerability_id"], "VCID-1234")

    def test_list_vulnerabilities_pagination(self):
        """
        Test listing vulnerabilities with pagination.
        """
        # Create additional vulnerabilities to trigger pagination
        for i in range(3, 15):
            Vulnerability.objects.create(
                vulnerability_id=f"VCID-{i}", summary=f"Test vulnerability {i}"
            )

        url = reverse("vulnerability-v2-list")
        response = self.client.get(url, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertIn("vulnerabilities", response.data["results"])
        self.assertIn("next", response.data)
        self.assertIn("previous", response.data)
        # The 'vulnerabilities' dictionary should contain vulnerabilities up to the page limit
        self.assertEqual(
            len(response.data["results"]["vulnerabilities"]), 10
        )  # Assuming default page size is 10


class PackageV2ViewSetTest(APITestCase):
    def setUp(self):
        # Create packages
        self.package1 = Package.objects.create(
            package_url="pkg:pypi/django@3.2", name="django", version="3.2", type="pypi"
        )
        self.package2 = Package.objects.create(
            package_url="pkg:npm/lodash@4.17.20", name="lodash", version="4.17.20", type="npm"
        )

        # Create vulnerabilities
        self.vuln1 = Vulnerability.objects.create(
            vulnerability_id="VCID-1234", summary="Test vulnerability 1"
        )
        self.vuln2 = Vulnerability.objects.create(
            vulnerability_id="VCID-5678", summary="Test vulnerability 2"
        )

        # Associate packages with vulnerabilities
        self.package1.affected_by_vulnerabilities.add(self.vuln1)
        self.package2.fixing_vulnerabilities.add(self.vuln2)

        self.user = ApiUser.objects.create_api_user(username="e@mail.com")
        self.auth = f"Token {self.user.auth_token.key}"
        self.client = APIClient(enforce_csrf_checks=True)
        self.client.credentials(HTTP_AUTHORIZATION=self.auth)

    def test_list_packages(self):
        """
        Test listing packages without filters.
        Should return a list of packages with their details and associated vulnerabilities.
        """
        url = reverse("package-v2-list")
        with self.assertNumQueries(32):
            response = self.client.get(url, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertIn("packages", response.data["results"])
        self.assertIn("vulnerabilities", response.data["results"])
        self.assertEqual(len(response.data["results"]["packages"]), 2)
        # Verify that vulnerabilities are included
        self.assertIsInstance(response.data["results"]["vulnerabilities"], dict)
        package_vulns = set()
        for package in response.data["results"]["packages"]:
            package_vulns.update(package["affected_by_vulnerabilities"])
            package_vulns.update(package["fixing_vulnerabilities"])
        self.assertTrue(
            all(vuln_id in response.data["results"]["vulnerabilities"] for vuln_id in package_vulns)
        )

    def test_filter_packages_by_purl(self):
        """
        Test filtering packages by one or more PURLs.
        """
        url = reverse("package-v2-list")
        with self.assertNumQueries(20):
            response = self.client.get(url, {"purl": "pkg:pypi/django@3.2"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]["packages"]), 1)
        self.assertEqual(response.data["results"]["packages"][0]["purl"], "pkg:pypi/django@3.2")

    def test_filter_packages_by_affected_vulnerability(self):
        """
        Test filtering packages by affected_by_vulnerability.
        """
        url = reverse("package-v2-list")
        with self.assertNumQueries(20):
            response = self.client.get(
                url, {"affected_by_vulnerability": "VCID-1234"}, format="json"
            )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]["packages"]), 1)
        self.assertEqual(response.data["results"]["packages"][0]["purl"], "pkg:pypi/django@3.2")

    def test_filter_packages_by_fixing_vulnerability(self):
        """
        Test filtering packages by fixing_vulnerability.
        """
        url = reverse("package-v2-list")
        with self.assertNumQueries(18):
            response = self.client.get(url, {"fixing_vulnerability": "VCID-5678"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]["packages"]), 1)
        self.assertEqual(response.data["results"]["packages"][0]["purl"], "pkg:npm/lodash@4.17.20")

    def test_package_serializer_fields(self):
        """
        Test that the PackageV2Serializer returns the correct fields and formats them correctly.
        """
        # Fetch the package
        package = Package.objects.get(package_url="pkg:pypi/django@3.2")

        # Ensure prefetched data is available for the serializer
        package = (
            Package.objects.filter(package_url="pkg:pypi/django@3.2")
            .prefetch_related(
                Prefetch(
                    "affected_by_vulnerabilities",
                    queryset=Vulnerability.objects.prefetch_related("fixed_by_packages"),
                    to_attr="prefetched_affected_vulnerabilities",
                )
            )
            .first()
        )

        # Serialize the package
        serializer = PackageV2Serializer(package)
        data = serializer.data

        # Verify the presence of required fields
        self.assertIn("purl", data)
        self.assertIn("affected_by_vulnerabilities", data)
        self.assertIn("fixing_vulnerabilities", data)
        self.assertIn("next_non_vulnerable_version", data)
        self.assertIn("latest_non_vulnerable_version", data)
        self.assertIn("risk_score", data)

        # Verify field values
        self.assertEqual(data["purl"], "pkg:pypi/django@3.2")
        self.assertEqual(data["next_non_vulnerable_version"], None)
        self.assertEqual(data["latest_non_vulnerable_version"], None)
        self.assertEqual(data["risk_score"], None)

        # Verify affected_by_vulnerabilities structure
        expected_affected_by_vulnerabilities = {
            "VCID-1234": {
                "code_fixes": [],
                "vulnerability_id": "VCID-1234",
                "fixed_by_packages": None,
            }
        }
        self.assertEqual(data["affected_by_vulnerabilities"], expected_affected_by_vulnerabilities)

        # Verify fixing_vulnerabilities structure
        expected_fixing_vulnerabilities = []
        self.assertEqual(data["fixing_vulnerabilities"], expected_fixing_vulnerabilities)

    def test_list_packages_pagination(self):
        """
        Test listing packages with pagination.
        """
        # Create additional packages to trigger pagination
        for i in range(3, 15):
            Package.objects.create(
                package_url=f"pkg:pypi/package{i}@1.0.{i}",
                name=f"package{i}",
                version=f"1.0.{i}",
                type="pypi",
            )

        url = reverse("package-v2-list")
        response = self.client.get(url, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertIn("packages", response.data["results"])
        self.assertIn("vulnerabilities", response.data["results"])
        self.assertIn("next", response.data)
        self.assertIn("previous", response.data)
        self.assertEqual(
            len(response.data["results"]["packages"]), 10
        )  # Assuming default page size is 10

    def test_invalid_vulnerability_filter(self):
        """
        Test filtering packages with an invalid vulnerability ID.
        Should return an empty list.
        """
        url = reverse("package-v2-list")
        with self.assertNumQueries(4):
            response = self.client.get(
                url, {"affected_by_vulnerability": "VCID-9999"}, format="json"
            )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]["packages"]), 0)

    def test_invalid_purl_filter(self):
        """
        Test filtering packages with an invalid PURL.
        Should return an empty list.
        """
        url = reverse("package-v2-list")
        with self.assertNumQueries(4):
            response = self.client.get(
                url, {"purl": "pkg:nonexistent/package@1.0.0"}, format="json"
            )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]["packages"]), 0)

    def test_get_affected_by_vulnerabilities(self):
        """
        Test the get_affected_by_vulnerabilities method in the serializer.
        """
        package = (
            Package.objects.filter(package_url="pkg:pypi/django@3.2")
            .prefetch_related(
                Prefetch(
                    "affected_by_vulnerabilities",
                    queryset=Vulnerability.objects.prefetch_related("fixed_by_packages"),
                    to_attr="prefetched_affected_vulnerabilities",
                )
            )
            .first()
        )

        serializer = PackageV2Serializer()
        vulnerabilities = serializer.get_affected_by_vulnerabilities(package)
        self.assertEqual(
            vulnerabilities,
            {
                "VCID-1234": {
                    "code_fixes": [],
                    "vulnerability_id": "VCID-1234",
                    "fixed_by_packages": None,
                }
            },
        )

    def test_get_fixing_vulnerabilities(self):
        """
        Test the get_fixing_vulnerabilities method in the serializer.
        """
        package = Package.objects.get(package_url="pkg:npm/lodash@4.17.20")
        serializer = PackageV2Serializer()
        vulnerabilities = serializer.get_fixing_vulnerabilities(package)
        self.assertEqual(vulnerabilities, ["VCID-5678"])

    def test_bulk_lookup_with_valid_purls(self):
        """
        Test bulk lookup with valid PURLs.
        Should return packages and their associated vulnerabilities.
        """
        url = reverse("package-v2-bulk-lookup")
        data = {"purls": ["pkg:pypi/django@3.2", "pkg:npm/lodash@4.17.20"]}
        with self.assertNumQueries(28):
            response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("packages", response.data)
        self.assertIn("vulnerabilities", response.data)
        self.assertEqual(len(response.data["packages"]), 2)
        # Verify that the returned data matches the packages
        purls = [package["purl"] for package in response.data["packages"]]
        self.assertIn("pkg:pypi/django@3.2", purls)
        self.assertIn("pkg:npm/lodash@4.17.20", purls)
        # Verify that vulnerabilities are included
        package_vulns = set()
        for package in response.data["packages"]:
            package_vulns.update(package["affected_by_vulnerabilities"])
            package_vulns.update(package["fixing_vulnerabilities"])
        self.assertTrue(
            all(vuln_id in response.data["vulnerabilities"] for vuln_id in package_vulns)
        )

    def test_bulk_lookup_with_invalid_purls(self):
        """
        Test bulk lookup with invalid PURLs.
        """
        url = reverse("package-v2-bulk-lookup")
        data = {"purls": ["pkg:pypi/nonexistent@1.0.0", "pkg:npm/unknown@0.0.1"]}
        with self.assertNumQueries(4):
            response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Since the packages don't exist, the response should be empty
        self.assertEqual(len(response.data["packages"]), 0)
        self.assertEqual(len(response.data["vulnerabilities"]), 0)

    def test_bulk_lookup_with_empty_purls(self):
        """
        Test bulk lookup with empty purls list.
        Should return 400 Bad Request.
        """
        url = reverse("package-v2-bulk-lookup")
        data = {"purls": []}
        with self.assertNumQueries(3):
            response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", response.data)
        self.assertIn("message", response.data)
        self.assertEqual(response.data["message"], "A non-empty 'purls' list of PURLs is required.")

    def test_bulk_search_with_valid_purls(self):
        """
        Test bulk search with valid PURLs.
        Should return packages and their associated vulnerabilities.
        """
        url = reverse("package-v2-bulk-search")
        data = {"purls": ["pkg:pypi/django@3.2", "pkg:npm/lodash@4.17.20"]}
        with self.assertNumQueries(28):
            response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("packages", response.data)
        self.assertIn("vulnerabilities", response.data)
        self.assertEqual(len(response.data["packages"]), 2)
        purls = [package["purl"] for package in response.data["packages"]]
        self.assertIn("pkg:pypi/django@3.2", purls)
        self.assertIn("pkg:npm/lodash@4.17.20", purls)
        # Verify that vulnerabilities are included
        package_vulns = set()
        for package in response.data["packages"]:
            package_vulns.update(package["affected_by_vulnerabilities"])
            package_vulns.update(package["fixing_vulnerabilities"])
        self.assertTrue(
            all(vuln_id in response.data["vulnerabilities"] for vuln_id in package_vulns)
        )

    def test_bulk_search_with_purl_only_true(self):
        """
        Test bulk search with purl_only set to True.
        Should return only the PURLs of vulnerable packages.
        """
        url = reverse("package-v2-bulk-search")
        data = {
            "purls": ["pkg:pypi/django@3.2", "pkg:npm/lodash@4.17.20"],
            "purl_only": True,
        }
        with self.assertNumQueries(17):
            response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Since purl_only=True, response should be a list of PURLs
        self.assertIsInstance(response.data, list)
        # Only vulnerable packages should be included
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data, ["pkg:pypi/django@3.2"])

    def test_bulk_search_with_plain_purl_true(self):
        """
        Test bulk search with plain_purl set to True.
        Should return packages grouped by plain PURLs.
        """
        # Create another package with the same name and version but different qualifiers
        Package.objects.create(
            name="django",
            version="3.2",
            type="pypi",
            qualifiers={"extension": "tar.gz"},
        )

        url = reverse("package-v2-bulk-search")
        data = {
            "purls": ["pkg:pypi/django@3.2", "pkg:pypi/django@3.2?extension=tar.gz"],
            "plain_purl": True,
        }
        with self.assertNumQueries(16):
            response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("packages", response.data)
        self.assertIn("vulnerabilities", response.data)
        # Since plain_purl=True, packages with the same type, namespace, name, version are grouped
        self.assertEqual(len(response.data["packages"]), 1)
        purl = response.data["packages"][0]["purl"]
        self.assertTrue(purl.startswith("pkg:pypi/django@3.2"))

    def test_bulk_search_with_purl_only_and_plain_purl_true(self):
        """
        Test bulk search with purl_only and plain_purl both set to True.
        Should return only the plain PURLs of vulnerable packages.
        """
        url = reverse("package-v2-bulk-search")
        data = {
            "purls": ["pkg:pypi/django@3.2", "pkg:pypi/django@3.1"],
            "purl_only": True,
            "plain_purl": True,
        }
        with self.assertNumQueries(11):
            response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Response should be a list of plain PURLs
        self.assertIsInstance(response.data, list)
        # Only one plain PURL should be returned for vulnerable packages
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data, ["pkg:pypi/django@3.2"])

    def test_bulk_search_with_invalid_purls(self):
        """
        Test bulk search with invalid PURLs.
        Should return an empty response.
        """
        url = reverse("package-v2-bulk-search")
        data = {"purls": ["pkg:pypi/nonexistent@1.0.0", "pkg:npm/unknown@0.0.1"]}
        with self.assertNumQueries(4):
            response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Since the packages don't exist, the response should be empty
        self.assertEqual(len(response.data["packages"]), 0)
        self.assertEqual(len(response.data["vulnerabilities"]), 0)

    def test_bulk_search_with_empty_purls(self):
        """
        Test bulk search with empty purls list.
        Should return 400 Bad Request.
        """
        url = reverse("package-v2-bulk-search")
        data = {"purls": []}
        with self.assertNumQueries(3):
            response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", response.data)
        self.assertIn("message", response.data)
        self.assertEqual(response.data["message"], "A non-empty 'purls' list of PURLs is required.")

    def test_all_vulnerable_packages(self):
        """
        Test the 'all' endpoint that returns all vulnerable package URLs.
        """
        url = reverse("package-v2-all")
        with self.assertNumQueries(4):
            response = self.client.get(url, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Since package1 is vulnerable, it should be returned
        expected_purls = ["pkg:pypi/django@3.2"]
        self.assertEqual(sorted(response.data), sorted(expected_purls))

    def test_lookup_with_valid_purl(self):
        """
        Test the 'lookup' endpoint with a valid PURL.
        Should return the package and its associated vulnerabilities.
        """
        url = reverse("package-v2-lookup")
        data = {"purl": "pkg:pypi/django@3.2"}
        with self.assertNumQueries(13):
            response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(1, len(response.data))
        self.assertIn("purl", response.data[0])
        self.assertIn("affected_by_vulnerabilities", response.data[0])
        self.assertIn("fixing_vulnerabilities", response.data[0])
        self.assertIn("next_non_vulnerable_version", response.data[0])
        self.assertIn("latest_non_vulnerable_version", response.data[0])
        self.assertEqual(response.data[0]["purl"], "pkg:pypi/django@3.2")
        self.assertEqual(
            response.data[0]["affected_by_vulnerabilities"],
            {
                "VCID-1234": {
                    "code_fixes": [],
                    "vulnerability_id": "VCID-1234",
                    "fixed_by_packages": None,
                }
            },
        )
        self.assertEqual(response.data[0]["fixing_vulnerabilities"], [])

    def test_lookup_with_invalid_purl(self):
        """
        Test the 'lookup' endpoint with a PURL that does not exist.
        Should return empty packages and vulnerabilities.
        """
        url = reverse("package-v2-lookup")
        data = {"purl": "pkg:pypi/nonexistent@1.0.0"}
        with self.assertNumQueries(4):
            response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # No packages or vulnerabilities should be returned
        self.assertEqual(len(response.data), 0)

    def test_lookup_with_missing_purl(self):
        """
        Test the 'lookup' endpoint without providing a 'purl'.
        Should return 400 Bad Request.
        """
        url = reverse("package-v2-lookup")
        data = {}
        with self.assertNumQueries(3):
            response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", response.data)
        self.assertIn("message", response.data)
        self.assertEqual(response.data["message"], "A 'purl' is required.")

    def test_lookup_with_invalid_purl_format(self):
        """
        Test the 'lookup' endpoint with an invalid PURL format.
        Should return empty packages and vulnerabilities.
        """
        url = reverse("package-v2-lookup")
        data = {"purl": "invalid_purl_format"}
        with self.assertNumQueries(4):
            response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # No packages or vulnerabilities should be returned
        self.assertEqual(len(response.data), 0)


class PipelineScheduleV2ViewSetTest(APITestCase):
    def setUp(self):
        # Reset the api throttling for anon user to properly test the
        # access on schedule endpoint.
        # DRF stores throttling state in cache, clear cache to reset throttling.
        # See https://www.django-rest-framework.org/api-guide/throttling/#setting-up-the-cache
        cache.clear()

        patcher = patch.object(PipelineSchedule, "create_new_job")
        self.mock_create_new_job = patcher.start()
        self.addCleanup(patcher.stop)

        self.mock_create_new_job.return_value = "work-id"

        self.schedule1 = PipelineSchedule.objects.create(
            pipeline_id="test_pipeline",
        )
        self.run1 = PipelineRun.objects.create(
            pipeline=self.schedule1,
        )

        self.admin_user = User.objects.create_superuser(
            username="admin_with_session",
            password="adminpassword",
            email="admin@test.com",
        )

        self.admin_token_only_user = ApiUser.objects.create_api_user(
            username="staff_with_token",
            is_staff=True,
        )
        self.admin_token_auth = f"Token {self.admin_token_only_user.auth_token.key}"

    def test_schedule_list_anon_user_permitted(self):
        response = self.client.get("/api/v2/schedule/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_schedule_retrieve_anon_user_permitted(self):
        response = self.client.get("/api/v2/schedule/test_pipeline/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @patch("vulnerabilities.models.PipelineSchedule.create_new_job")
    def test_create_schedule_anon_user_not_permitted(self, mock_create_new_job):
        mock_create_new_job.return_value = "work-id2"

        data = {"pipeline_id": "test_pipeline2"}
        response = self.client.post("/api/v2/schedule/", data, format="json")

        self.assertNotEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(PipelineSchedule.objects.count(), 1)

    @patch("vulnerabilities.models.PipelineSchedule.create_new_job")
    def test_create_schedule_with_staff_token_not_permitted(self, mock_create_new_job):
        self.client = APIClient(enforce_csrf_checks=True)
        self.client.credentials(HTTP_AUTHORIZATION=self.admin_token_auth)

        mock_create_new_job.return_value = "work-id3"

        data = {"pipeline_id": "test_pipeline3"}
        response = self.client.post("/api/v2/schedule/", data, format="json")

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertNotEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(PipelineSchedule.objects.count(), 1)

    @patch("vulnerabilities.models.PipelineSchedule.create_new_job")
    def test_create_schedule_with_staff_session_permitted(self, mock_create_new_job):
        mock_create_new_job.return_value = "work-id4"
        self.client.login(username="admin_with_session", password="adminpassword")

        data = {"pipeline_id": "test_pipeline3"}
        response = self.client.post("/api/v2/schedule/", data, format="json")

        self.assertNotEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(PipelineSchedule.objects.count(), 2)

    @patch("vulnerabilities.models.PipelineSchedule.create_new_job")
    def test_schedule_update_anon_user_not_permitted(self, mock_create_new_job):
        mock_create_new_job.return_value = "work-id5"

        data = {"run_interval": 2}
        response = self.client.patch("/api/v2/schedule/test_pipeline/", data, format="json")
        self.schedule1.refresh_from_db()

        self.assertNotEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(self.schedule1.run_interval, 1)

    @patch("vulnerabilities.models.PipelineSchedule.create_new_job")
    def test_schedule_update_with_staff_token_not_permitted(self, mock_create_new_job):
        self.client = APIClient(enforce_csrf_checks=True)
        self.client.credentials(HTTP_AUTHORIZATION=self.admin_token_auth)

        mock_create_new_job.return_value = "work-id6"

        data = {"run_interval": 2}
        response = self.client.patch("/api/v2/schedule/test_pipeline/", data, format="json")
        self.schedule1.refresh_from_db()

        self.assertNotEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(self.schedule1.run_interval, 1)

    @patch("vulnerabilities.models.PipelineSchedule.create_new_job")
    def test_schedule_update_with_staff_session_permitted(self, mock_create_new_job):
        mock_create_new_job.return_value = "work-id7"
        self.client.login(username="admin_with_session", password="adminpassword")

        data = {"run_interval": 2}
        response = self.client.patch("/api/v2/schedule/test_pipeline/", data, format="json")
        self.schedule1.refresh_from_db()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(self.schedule1.run_interval, 2)
