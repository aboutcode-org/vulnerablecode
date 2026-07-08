#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from unittest.mock import patch

from django.core.cache import cache
from django.urls import reverse
from django.utils import timezone
from packageurl import PackageURL
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework.test import APITestCase
from univers.version_range import PypiVersionRange

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import PackageCommitPatchData
from vulnerabilities.models import AdvisorySet
from vulnerabilities.models import AdvisorySetMember
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import ImpactedPackageAffecting
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
            pipeline_id="ghsa_pipeline_v2",
            datasource_id="ghsa",
            logger=self.logger.write,
        )
        self.advisory.save()

        self.package = PackageV2.objects.from_purl(purl="pkg:pypi/sample@1.0.0")
        self.impact = ImpactedPackage.objects.create(
            advisory=self.advisory,
            base_purl="pkg:pypi/sample",
        )
        self.impact.affecting_packages.add(self.package)

        self.client = APIClient(enforce_csrf_checks=True)

        self.allow_request_patcher = patch(
            "vulnerabilities.throttling.PermissionBasedUserRateThrottle.allow_request",
            return_value=True,
        )
        self.allow_request_patcher.start()
        self.addCleanup(self.allow_request_patcher.stop)

        self.anon_patcher = patch(
            "rest_framework.throttling.AnonRateThrottle.allow_request",
            return_value=True,
        )
        self.anon_patcher.start()
        self.addCleanup(self.anon_patcher.stop)

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
                HTTP_USER_AGENT="VCIO_API_AGENT",
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        results = response.data["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], "pkg:pypi/sample@1.0.0")

    def test_packages_post_with_details(self):
        url = reverse("package-v3-list")

        with self.assertNumQueries(11):
            response = self.client.post(
                url,
                data={
                    "purls": ["pkg:pypi/sample@1.0.0"],
                    "details": True,
                },
                format="json",
                HTTP_USER_AGENT="VCIO_API_AGENT",
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
                HTTP_USER_AGENT="VCIO_API_AGENT",
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        advisory = response.data["results"][0]
        self.assertEqual(advisory["advisory_id"], "GHSA-1234")
        self.assertEqual(advisory["advisory_uid"], "ghsa/GHSA-1234")

    def test_affected_by_advisories_list(self):
        url = reverse("affected-by-advisories-list")

        with self.assertNumQueries(11):
            response = self.client.get(
                url, {"purl": "pkg:pypi/sample@1.0.0"}, HTTP_USER_AGENT="VCIO_API_AGENT"
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        results = response.data["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["advisory_id"], "GHSA-1234")

    def test_fixing_advisories_list_empty(self):
        url = reverse("fixing-advisories-list")

        with self.assertNumQueries(3):
            response = self.client.get(
                url, {"purl": "pkg:pypi/sample@1.0.0"}, HTTP_USER_AGENT="VCIO_API_AGENT"
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 0)

    def test_packages_pagination(self):
        url = reverse("package-v3-list")

        response = self.client.post(
            url, data={"purls": []}, format="json", HTTP_USER_AGENT="VCIO_API_AGENT"
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
            HTTP_USER_AGENT="VCIO_API_AGENT",
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

            advisory_obj = insert_advisory_v2(advisory, "ghsa_importer", print, "ghsa", 100)
            cur = timezone.now()
            advisory_obj._all_impacts_unfurled_at = cur
            advisory_obj.save()

        self.client = APIClient(enforce_csrf_checks=True)
        self.allow_request_patcher = patch(
            "vulnerabilities.throttling.PermissionBasedUserRateThrottle.allow_request",
            return_value=True,
        )
        self.allow_request_patcher.start()
        self.addCleanup(self.allow_request_patcher.stop)

        self.anon_patcher = patch(
            "rest_framework.throttling.AnonRateThrottle.allow_request",
            return_value=True,
        )
        self.anon_patcher.start()
        self.addCleanup(self.anon_patcher.stop)

    def test_advisories_post(self):
        url = reverse("advisory-v3-list")

        with self.assertNumQueries(10):
            response = self.client.post(
                url,
                data={"purls": ["pkg:pypi/sample@1.0.0"]},
                format="json",
                HTTP_USER_AGENT="VCIO_API_AGENT",
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 100)
        advisory = response.data["results"][0]
        self.assertEqual(advisory["advisory_id"], "GHSA-12341")


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

        advisory_obj = insert_advisory_v2(advisory, "ghsa_importer", print, "ghsa", 100)
        cur = timezone.now()
        advisory_obj._all_impacts_unfurled_at = cur
        advisory_obj.save()

        self.client = APIClient(enforce_csrf_checks=True)

        self.allow_request_patcher = patch(
            "vulnerabilities.throttling.PermissionBasedUserRateThrottle.allow_request",
            return_value=True,
        )
        self.allow_request_patcher.start()
        self.addCleanup(self.allow_request_patcher.stop)

        self.anon_patcher = patch(
            "rest_framework.throttling.AnonRateThrottle.allow_request",
            return_value=True,
        )
        self.anon_patcher.start()
        self.addCleanup(self.anon_patcher.stop)

    def test_get_all_vulnerable_purls(self):
        url = reverse("package-v3-list")

        with self.assertNumQueries(4):
            response = self.client.post(
                url,
                data={
                    "purls": [],
                },
                format="json",
                HTTP_USER_AGENT="VCIO_API_AGENT",
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        results = response.data["results"]
        self.assertEqual(len(results), 100)
        self.assertIn("next", response.data)


class PackageCommitPatchTests(APITestCase):
    def setUp(self):
        self.advisory = AdvisoryDataV2(
            advisory_id="AVID-123",
            aliases=[],
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL(type="pypi", name="sample"),
                    affected_version_range=PypiVersionRange.from_string("vers:pypi/=1.0.0"),
                    introduced_by_commit_patches=[
                        PackageCommitPatchData(
                            vcs_url="https://github.com/aboutcode-org/sample",
                            commit_hash="06580c7f99c6fde7bcf18e30bdcc61f081430957",
                        )
                    ],
                    fixed_by_commit_patches=[
                        PackageCommitPatchData(
                            vcs_url="https://github.com/aboutcode-org/sample",
                            commit_hash="98e516011d6e096e25247b82fc5f196bbeecff10",
                        )
                    ],
                )
            ],
            url="https://github.com/aboutcode-org/sample",
        )

        self.allow_request_patcher = patch(
            "vulnerabilities.throttling.PermissionBasedUserRateThrottle.allow_request",
            return_value=True,
        )
        self.allow_request_patcher.start()
        self.addCleanup(self.allow_request_patcher.stop)

        self.anon_patcher = patch(
            "rest_framework.throttling.AnonRateThrottle.allow_request",
            return_value=True,
        )
        self.anon_patcher.start()
        self.addCleanup(self.anon_patcher.stop)

        self.advisory = insert_advisory_v2(self.advisory, "importer_1", print, 100)
        self.advisory.is_latest = True
        self.advisory._all_impacts_unfurled_at = timezone.now()
        self.advisory.save()
        self.package, _ = PackageV2.objects.get_or_create(
            package_url="pkg:pypi/sample@1.0.0",
            defaults={"name": "sample", "type": "pypi", "version": "1.0.0"},
        )

        impacted_package = ImpactedPackage.objects.get(advisory=self.advisory)
        ImpactedPackageAffecting.objects.get_or_create(
            package=self.package,
            impacted_package=impacted_package,
        )
        adv_set = AdvisorySet.objects.create(
            package=self.package, primary_advisory=self.advisory, relation_type="affecting"
        )
        AdvisorySetMember.objects.create(advisory_set=adv_set, advisory=self.advisory)

        self.client = APIClient(enforce_csrf_checks=True)

    def test_packages_commit_patch(self):
        url = reverse("package-v3-list")
        response = self.client.post(
            url,
            data={"purls": ["pkg:pypi/sample@1.0.0"], "details": True, "reachability": True},
            format="json",
            HTTP_USER_AGENT="VCIO_API_AGENT",
        )

        assert response.status_code == 200
        results = response.data["results"]
        assert len(results) == 1
        pkg = results[0]
        assert pkg["purl"] == "pkg:pypi/sample@1.0.0"

        vulns = pkg.get("affected_by_vulnerabilities", [])
        assert len(vulns) == 1
        advisory_data = vulns[0]

        assert advisory_data["advisory_id"] == "AVID-123"
        assert advisory_data["introduced_in_patches"] == [
            {
                "commit_hash": "06580c7f99c6fde7bcf18e30bdcc61f081430957",
                "vcs_url": "https://github.com/aboutcode-org/sample",
            }
        ]

        assert advisory_data["fixed_in_patches"] == [
            {
                "commit_hash": "98e516011d6e096e25247b82fc5f196bbeecff10",
                "vcs_url": "https://github.com/aboutcode-org/sample",
            }
        ]


class PackageCommitPatchComplexTest(APITestCase):
    def setUp(self):
        self.package, _ = PackageV2.objects.get_or_create(
            package_url="pkg:pypi/sample@1.0.0",
            defaults={"name": "sample", "type": "pypi", "version": "1.0.0"},
        )

        self.allow_request_patcher = patch(
            "vulnerabilities.throttling.PermissionBasedUserRateThrottle.allow_request",
            return_value=True,
        )
        self.allow_request_patcher.start()
        self.addCleanup(self.allow_request_patcher.stop)

        self.anon_patcher = patch(
            "rest_framework.throttling.AnonRateThrottle.allow_request",
            return_value=True,
        )
        self.anon_patcher.start()
        self.addCleanup(self.anon_patcher.stop)

        self.advisory_data = AdvisoryDataV2(
            advisory_id="AVID-123",
            aliases=[],
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL(type="pypi", name="sample"),
                    affected_version_range=PypiVersionRange.from_string("vers:pypi/=1.0.0"),
                    introduced_by_commit_patches=[
                        PackageCommitPatchData(
                            vcs_url="https://github.com/aboutcode-org/sample",
                            commit_hash="06580c7f99c6fde7bcf18e30bdcc61f081430957",
                        )
                    ],
                    fixed_by_commit_patches=[
                        PackageCommitPatchData(
                            vcs_url="https://github.com/aboutcode-org/sample",
                            commit_hash="98e516011d6e096e25247b82fc5f196bbeecff10",
                        )
                    ],
                )
            ],
            url="https://github.com/aboutcode-org/sample",
        )

        self.advisory = insert_advisory_v2(self.advisory_data, "importer_1", print, 100)
        self.advisory.is_latest = True
        self.advisory._all_impacts_unfurled_at = timezone.now()
        self.advisory.save()

        impacted_package = ImpactedPackage.objects.get(advisory=self.advisory)
        ImpactedPackageAffecting.objects.get_or_create(
            package=self.package,
            impacted_package=impacted_package,
        )

        self.adv_set = AdvisorySet.objects.create(
            package=self.package, primary_advisory=self.advisory, relation_type="affecting"
        )
        AdvisorySetMember.objects.create(advisory_set=self.adv_set, advisory=self.advisory)

        self.member_advisory_data = AdvisoryDataV2(
            advisory_id="AVID-456",
            aliases=[],
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL(type="pypi", name="sample"),
                    affected_version_range=PypiVersionRange.from_string("vers:pypi/=1.0.0"),
                    introduced_by_commit_patches=[
                        PackageCommitPatchData(
                            vcs_url="https://github.com/aboutcode-org/sample",
                            commit_hash="98e516011d6e096e25247b82fc5f196bbeecff10",
                        )
                    ],
                    fixed_by_commit_patches=[
                        PackageCommitPatchData(
                            vcs_url="https://github.com/aboutcode-org/sample",
                            commit_hash="2fc5f196bbeecff1098e516011d6e096e25247b8",
                        )
                    ],
                )
            ],
            url="https://github.com/aboutcode-org/sample-member",
        )

        self.member_advisory = insert_advisory_v2(
            self.member_advisory_data, "importer_1", print, 100
        )
        self.member_advisory.is_latest = True
        self.member_advisory._all_impacts_unfurled_at = timezone.now()
        self.member_advisory.save()

        member_impacted_package = ImpactedPackage.objects.get(advisory=self.member_advisory)
        ImpactedPackageAffecting.objects.get_or_create(
            package=self.package,
            impacted_package=member_impacted_package,
        )

        AdvisorySetMember.objects.create(advisory_set=self.adv_set, advisory=self.member_advisory)
        self.client = APIClient(enforce_csrf_checks=True)

    def test_packages_commit_patch(self):
        url = reverse("package-v3-list")
        response = self.client.post(
            url,
            data={"purls": ["pkg:pypi/sample@1.0.0"], "details": True, "reachability": True},
            format="json",
            HTTP_USER_AGENT="VCIO_API_AGENT",
        )

        assert response.status_code == 200
        results = response.data["results"]
        pkg = results[0]
        vulns = pkg.get("affected_by_vulnerabilities", [])
        advisory_data = vulns[0]

        assert advisory_data["advisory_id"] == "AVID-123"
        assert {
            "commit_hash": "06580c7f99c6fde7bcf18e30bdcc61f081430957",
            "vcs_url": "https://github.com/aboutcode-org/sample",
        } in advisory_data["introduced_in_patches"]

    def test_advisory_set_member_patches_aggregation(self):
        url = reverse("package-v3-list")

        with patch("vulnerabilities.views.TYPES_WITH_MULTIPLE_IMPORTERS", ["pypi"]):
            response = self.client.post(
                url,
                data={"purls": ["pkg:pypi/sample@1.0.0"], "details": True, "reachability": True},
                format="json",
                HTTP_USER_AGENT="VCIO_API_AGENT",
            )

        assert response.status_code == 200
        results = response.data["results"]
        assert len(results) == 1

        pkg = results[0]
        vulns = pkg.get("affected_by_vulnerabilities", [])
        assert len(vulns) == 1
        advisory_data = vulns[0]
        assert advisory_data["advisory_id"] == "AVID-123"

        introduced_hashes = [
            patch["commit_hash"] for patch in advisory_data["introduced_in_patches"]
        ]
        assert "06580c7f99c6fde7bcf18e30bdcc61f081430957" in introduced_hashes
        assert "98e516011d6e096e25247b82fc5f196bbeecff10" in introduced_hashes

        fixed_hashes = [patch["commit_hash"] for patch in advisory_data["fixed_in_patches"]]
        assert "98e516011d6e096e25247b82fc5f196bbeecff10" in fixed_hashes
        assert "2fc5f196bbeecff1098e516011d6e096e25247b8" in fixed_hashes


class TestPackageTypesView(APITestCase):
    def setUp(self):
        self.allow_request_patcher = patch(
            "vulnerabilities.throttling.PermissionBasedUserRateThrottle.allow_request",
            return_value=True,
        )
        self.allow_request_patcher.start()
        self.addCleanup(self.allow_request_patcher.stop)

        self.anon_patcher = patch(
            "rest_framework.throttling.AnonRateThrottle.allow_request",
            return_value=True,
        )
        self.anon_patcher.start()
        self.addCleanup(self.anon_patcher.stop)

    def test_returns_distinct_types_and_caches_response(self):
        cache.delete("package_types")

        PackageV2.objects.create(
            package_url="pkg:npm/test1@1.0.0",
            plain_package_url="pkg:npm/test1",
            type="npm",
            name="test1",
        )

        PackageV2.objects.create(
            package_url="pkg:npm/test2@1.0.0",
            plain_package_url="pkg:npm/test2",
            type="npm",
            name="test2",
        )

        PackageV2.objects.create(
            package_url="pkg:pypi/test@1.0.0",
            plain_package_url="pkg:pypi/test",
            type="pypi",
            name="test",
        )

        client = APIClient(enforce_csrf_checks=True)

        response = client.get(reverse("package-types-list"), HTTP_USER_AGENT="VCIO_API_AGENT")

        assert response.status_code == 200
        assert response.json() == ["npm", "pypi"]

        assert cache.get("package_types") == ["npm", "pypi"]
