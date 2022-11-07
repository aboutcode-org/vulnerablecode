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
                url="test-url",
                reference_id="test-id",
            )
        ]
        self.advisory = Advisory.objects.create(
            summary="summary",
            affected_packages=[pkg.to_dict() for pkg in aff_pkg],
            references=[ref.to_dict() for ref in refs],
            date_published="2020-01-01",
            date_collected="2020-01-01",
        )

    def test_count_of_vulns(self):
        # Run the improver twice
        # We should get single vulnerability for same
        # advisory when ran through same improver
        ImproveRunner(DefaultImprover).run()
        ImproveRunner(DefaultImprover).run()
        self.assertEqual(Advisory.objects.count(), 1)
        self.assertEqual(Vulnerability.objects.count(), 1)
