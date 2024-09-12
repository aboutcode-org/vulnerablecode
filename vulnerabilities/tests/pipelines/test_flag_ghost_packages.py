#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


from pathlib import Path
from unittest import mock

from django.test import TestCase
from fetchcode.package_versions import PackageVersion
from packageurl import PackageURL

from vulnerabilities.models import Package
from vulnerabilities.pipelines import flag_ghost_packages
from vulnerabilities.tests.pipelines import TestLogger


class FlagGhostPackagePipelineTest(TestCase):
    data = Path(__file__).parent.parent / "test_data"

    @mock.patch("vulnerabilities.pipelines.flag_ghost_packages.versions")
    def test_flag_ghost_package(self, mock_fetchcode_versions):
        Package.objects.create(type="pypi", name="foo", version="2.3.0")
        Package.objects.create(type="pypi", name="foo", version="3.0.0")

        mock_fetchcode_versions.return_value = [
            PackageVersion(value="2.3.0"),
        ]
        interesting_packages_qs = Package.objects.all()
        base_purl = PackageURL(type="pypi", name="foo")

        self.assertEqual(0, Package.objects.filter(is_ghost=True).count())

        flagged_package_count = flag_ghost_packages.flag_ghost_packages(
            base_purl=base_purl,
            packages=interesting_packages_qs,
        )
        self.assertEqual(1, flagged_package_count)
        self.assertEqual(1, Package.objects.filter(is_ghost=True).count())

    @mock.patch("vulnerabilities.pipelines.flag_ghost_packages.versions")
    def test_detect_and_flag_ghost_packages(self, mock_fetchcode_versions):
        Package.objects.create(type="pypi", name="foo", version="2.3.0")
        Package.objects.create(type="pypi", name="foo", version="3.0.0")
        Package.objects.create(
            type="deb",
            namespace="debian",
            name="foo",
            version="3.0.0",
            qualifiers={"distro": "trixie"},
        )

        mock_fetchcode_versions.return_value = [
            PackageVersion(value="2.3.0"),
        ]

        self.assertEqual(3, Package.objects.count())
        self.assertEqual(0, Package.objects.filter(is_ghost=True).count())

        logger = TestLogger()

        flag_ghost_packages.detect_and_flag_ghost_packages(logger=logger.write)
        expected = "Successfully flagged 1 ghost Packages"

        self.assertIn(expected, logger.getvalue())
        self.assertEqual(1, Package.objects.filter(is_ghost=True).count())
