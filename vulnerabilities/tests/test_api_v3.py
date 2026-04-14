#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.urls import reverse
from packageurl import PackageURL
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework.test import APITestCase
from univers.version_range import PypiVersionRange

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import PackageV2
from vulnerabilities.pipes.advisory import insert_advisory_v2
from vulnerabilities.tests.pipelines import TestLogger


class APIV3TestCase(APITestCase):
    def setUp(self):
        from vulnerabilities.models import ImpactedPackage

        self.logger = TestLogger()
        self.advisory = insert_advisory_v2(
            advisory=AdvisoryDataV2(
                summary="summary",
                advisory_id="GHSA-1234",
                url="https://example.com/advisory",
            ),
            pipeline_id="ghsa",
            logger=self.logger.write,
        )

        self.package = PackageV2.objects.from_purl(purl="pkg:pypi/sample@1.0.0")
        self.impact = ImpactedPackage.objects.create(
            advisory=self.advisory, base_purl="pkg:pypi/sample"
        )
        self.impact.affecting_packages.add(self.package)

        self.client = APIClient(enforce_csrf_checks=True)

    def test_packages_post_without_details(self):
        url = reverse("package-v3-list")

        with self.assertNumQueries(4):
            response = self.client.post(
                url,
                data={
                    "purls": ["pkg:pypi/sample@1.0.0"],
                    "details": False,
                },
                format="json",
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        results = response.data["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], "pkg:pypi/sample@1.0.0")

    def test_packages_post_with_details(self):
        url = reverse("package-v3-list")

        with self.assertNumQueries(33):
            response = self.client.post(
                url,
                data={
                    "purls": ["pkg:pypi/sample@1.0.0"],
                    "details": True,
                },
                format="json",
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        pkg = response.data["results"][0]
        self.assertEqual(pkg["purl"], "pkg:pypi/sample@1.0.0")

    def test_advisories_post(self):
        url = reverse("advisory-v3-list")

        with self.assertNumQueries(10):
            response = self.client.post(
                url,
                data={"purls": ["pkg:pypi/sample@1.0.0"]},
                format="json",
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        advisory = response.data["results"][0]
        self.assertEqual(advisory["advisory_id"], "ghsa/GHSA-1234")

    def test_affected_by_advisories_list(self):
        url = reverse("affected-by-advisories-list")

        with self.assertNumQueries(11):
            response = self.client.get(
                url,
                {"purl": "pkg:pypi/sample@1.0.0"},
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        results = response.data["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["advisory_id"], "ghsa/GHSA-1234")

    def test_fixing_advisories_list_empty(self):
        url = reverse("fixing-advisories-list")

        with self.assertNumQueries(3):
            response = self.client.get(
                url,
                {"purl": "pkg:pypi/sample@1.0.0"},
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 0)

    def test_packages_pagination(self):
        url = reverse("package-v3-list")

        response = self.client.post(
            url,
            data={"purls": []},
            format="json",
        )

        self.assertEqual(response.status_code, 200)

        self.assertIn("count", response.data)
        self.assertEqual(response.data["count"], 1)
        self.assertIn("results", response.data)
        self.assertIn("next", response.data)

    def test_packages_ignore_qualifiers_subpath(self):
        url = reverse("package-v3-list")

        response = self.client.post(
            url,
            data={
                "purls": ["pkg:pypi/sample@1.0.0?foo=bar"],
                "ignore_qualifiers_subpath": True,
                "details": False,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertIn("pkg:pypi/sample@1.0.0", response.data["results"])


class APIV3TestCaseOnePackageMultipleAdvisories(APITestCase):
    def setUp(self):
        from vulnerabilities.importer import AdvisoryDataV2
        from vulnerabilities.importer import AffectedPackageV2

        affected_packages = []
        affected_packages.append(
            AffectedPackageV2(
                package=PackageURL(type="pypi", name="sample"),
                affected_version_range=PypiVersionRange.from_string("vers:pypi/=1.0.0"),
            )
        )

        for i in range(1, 102):
            advisory = AdvisoryDataV2(
                advisory_id=f"GHSA-1234{i}",
                aliases=[f"CVE-2021-1234{i}"],
                summary="Sample advisory",
                affected_packages=affected_packages,
                url="https://example.com/advisory",
                original_advisory_text="Sample advisory text",
            )

            insert_advisory_v2(advisory, "ghsa_importer", print, 100)

        self.client = APIClient(enforce_csrf_checks=True)

    def test_advisories_post(self):
        url = reverse("advisory-v3-list")

        with self.assertNumQueries(10):
            response = self.client.post(
                url,
                data={"purls": ["pkg:pypi/sample@1.0.0"]},
                format="json",
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 100)
        advisory = response.data["results"][0]
        self.assertEqual(advisory["advisory_id"], "ghsa_importer/GHSA-12341")


class APIV3TestCaseOneAdvisoryMultiplePackages(APITestCase):
    def setUp(self):
        from vulnerabilities.importer import AdvisoryDataV2
        from vulnerabilities.importer import AffectedPackageV2

        affected_packages = []
        for i in range(1, 102):
            affected_packages.append(
                AffectedPackageV2(
                    package=PackageURL(type="pypi", name=f"sample{i}"),
                    affected_version_range=PypiVersionRange.from_string("vers:pypi/=1.0.0"),
                )
            )

        advisory = AdvisoryDataV2(
            advisory_id=f"GHSA-1234{i}",
            aliases=[f"CVE-2021-1234{i}"],
            summary="Sample advisory",
            affected_packages=affected_packages,
            url="https://example.com/advisory",
            original_advisory_text="Sample advisory text",
        )

        insert_advisory_v2(advisory, "ghsa_importer", print, 100)

        self.client = APIClient(enforce_csrf_checks=True)

    def test_get_all_vulnerable_purls(self):
        url = reverse("package-v3-list")

        with self.assertNumQueries(4):
            response = self.client.post(
                url,
                data={
                    "purls": [],
                },
                format="json",
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        results = response.data["results"]
        self.assertEqual(len(results), 100)
        self.assertIn("next", response.data)
