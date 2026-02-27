#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


from datetime import datetime
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from packageurl import PackageURL
from univers.version_range import VersionRange

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines.v2_improvers.unfurl_version_range import UnfurlVersionRangePipeline
from vulnerabilities.pipes.advisory import insert_advisory_v2
from vulnerabilities.tests.pipelines import TestLogger


class TestUnfurlVersionRangePipeline(TestCase):
    def setUp(self):
        self.logger = TestLogger()
        advisory1 = AdvisoryDataV2(
            summary="Test advisory",
            aliases=["CVE-2025-0001"],
            references=[],
            severities=[],
            weaknesses=[],
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL.from_string("pkg:npm/foobar"),
                    affected_version_range=VersionRange.from_string("vers:npm/>3.2.1|<4.0.0"),
                    fixed_version_range=VersionRange.from_string("vers:npm/4.0.0"),
                    introduced_by_commit_patches=[],
                    fixed_by_commit_patches=[],
                ),
            ],
            patches=[],
            advisory_id="GHSA-1234",
            date_published=datetime.now() - timedelta(days=10),
            url="https://example.com/advisory",
        )
        insert_advisory_v2(
            advisory=advisory1,
            pipeline_id="test_pipeline_v2",
            logger=self.logger.write,
        )

    @patch("vulnerabilities.pipelines.v2_improvers.unfurl_version_range.get_purl_versions")
    def test_affecting_version_range_unfurl(self, mock_fetch):
        self.assertEqual(1, PackageV2.objects.count())
        mock_fetch.return_value = {"3.4.1", "3.9.0", "2.1.0", "4.0.0", "4.1.0"}
        pipeline = UnfurlVersionRangePipeline()
        pipeline.execute()

        advisory = AdvisoryV2.objects.first()
        impact = advisory.impacted_packages.first()

        self.assertEqual(3, PackageV2.objects.count())
        self.assertEqual(1, impact.fixed_by_packages.count())
        self.assertEqual(2, impact.affecting_packages.count())
