#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.test import TestCase
from packageurl import PackageURL
from univers.versions import PypiVersion

from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.improve_runner import ImproveRunner
from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.models import Advisory
from vulnerabilities.models import Vulnerability


class TestAdvisoryWihoutAlias(TestCase):
    def setUp(self):
        aff_pkg = [
            AffectedPackage(
                package=PackageURL(
                    name="django",
                    type="pypi",
                ),
                fixed_version=PypiVersion("0.1.0"),
            )
        ]
        refs = [
            Reference(
                url="https://www.djangoproject.com/weblog/2015/sep/25/security-releases/",
                reference_id="test-id",
            ),
            Reference(
                url="https://www.djangoproject.com/web/2015/sep/25/security-releases/",
                reference_id="test1-id",
            ),
        ]
        Advisory.objects.create(
            summary="summary",
            affected_packages=[pkg.to_dict() for pkg in aff_pkg],
            references=[ref.to_dict() for ref in refs],
            date_published="2020-01-01",
            date_collected="2020-01-01",
        )
        aff_pkg_2 = aff_pkg + [
            AffectedPackage(
                package=PackageURL(
                    name="flask",
                    type="pypi",
                ),
                fixed_version=PypiVersion("0.1.0"),
            )
        ]
        # Advisory object with different affected packages
        Advisory.objects.create(
            summary="summary",
            affected_packages=[pkg.to_dict() for pkg in aff_pkg_2],
            references=[ref.to_dict() for ref in refs],
            date_published="2020-01-01",
            date_collected="2020-01-01",
        )

        refs_2 = refs + [
            Reference(
                url="https://www.djangoproject.com/web/2016/sep/25/security-releases/",
                reference_id="test2-id",
            )
        ]
        # Advisory object with different references
        Advisory.objects.create(
            summary="summary",
            affected_packages=[pkg.to_dict() for pkg in aff_pkg],
            references=[ref.to_dict() for ref in refs_2],
            date_published="2020-01-01",
            date_collected="2020-01-01",
        )

        # Advisory object with different summary, refs and affected packages
        Advisory.objects.create(
            summary="diff-summary",
            affected_packages=[pkg.to_dict() for pkg in aff_pkg_2],
            references=[ref.to_dict() for ref in refs_2],
            date_published="2020-01-01",
            date_collected="2020-01-01",
        )

    def test_count_of_vulns(self):
        # Run the improver twice
        # We should get single vulnerability for same
        # advisory when ran through same improver
        ImproveRunner(DefaultImprover).run()
        ImproveRunner(DefaultImprover).run()
        self.assertEqual(Advisory.objects.count(), 4)
        self.assertEqual(Vulnerability.objects.count(), 2)
