#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import io
from pathlib import Path
from unittest import mock

from django.test import TestCase
from fetchcode.package_versions import PackageVersion

from vulnerabilities.models import Package
from vulnerabilities.pipelines import remove_ghost_packages


class RemoveGhostPackagePipelineTest(TestCase):
    data = Path(__file__).parent.parent / "test_data"

    @mock.patch("vulnerabilities.pipelines.remove_ghost_packages.versions")
    def test_remove_ghost_package(self, mock_fetchcode_versions):
        Package.objects.create(type="pypi", name="foo", version="2.3.0")
        Package.objects.create(type="pypi", name="foo", version="3.0.0")

        mock_fetchcode_versions.return_value = [
            PackageVersion(value="2.3.0"),
        ]
        interesting_packages_qs = Package.objects.all()
        target_package = {
            "type": "pypi",
            "namespace": "",
            "name": "foo",
        }

        self.assertEqual(2, Package.objects.count())

        removed_package_count = remove_ghost_packages.remove_ghost_package(
            package=target_package,
            interesting_packages_qs=interesting_packages_qs,
        )
        self.assertEqual(1, removed_package_count)
        self.assertEqual(1, Package.objects.count())

    @mock.patch("vulnerabilities.pipelines.remove_ghost_packages.versions")
    def test_remove_ghost_package(self, mock_fetchcode_versions):
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

        buffer = io.StringIO()
        remove_ghost_packages.detect_and_remove_ghost_packages(logger=buffer.write)
        expected = "Successfully removed 1 ghost Packages"

        self.assertIn(expected, buffer.getvalue())
        self.assertEqual(2, Package.objects.count())
