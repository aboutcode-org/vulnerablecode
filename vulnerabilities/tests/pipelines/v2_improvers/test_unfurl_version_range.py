#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


from unittest.mock import patch

from django.test import TestCase

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines.v2_improvers.unfurl_version_range import UnfurlVersionRangePipeline


class TestUnfurlVersionRangePipeline(TestCase):
    def setUp(self):
        self.advisory1 = AdvisoryV2.objects.create(
            datasource_id="ghsa",
            advisory_id="GHSA-1234",
            avid="ghsa/GHSA-1234",
            unique_content_id="f" * 64,
            url="https://example.com/advisory",
            date_collected="2025-07-01T00:00:00Z",
        )

        self.impact1 = ImpactedPackage.objects.create(
            advisory=self.advisory1,
            base_purl="pkg:npm/foobar",
            affecting_vers="vers:npm/>3.2.1|<4.0.0",
            fixed_vers=None,
        )

    @patch("vulnerabilities.pipelines.v2_improvers.unfurl_version_range.get_purl_versions")
    def test_affecting_version_range_unfurl(self, mock_fetch):
        self.assertEqual(0, PackageV2.objects.count())
        mock_fetch.return_value = {"3.4.1", "3.9.0", "2.1.0", "4.0.0", "4.1.0"}
        pipeline = UnfurlVersionRangePipeline()
        pipeline.execute()

        self.assertEqual(2, PackageV2.objects.count())
        self.assertEqual(2, self.impact1.affecting_packages.count())
