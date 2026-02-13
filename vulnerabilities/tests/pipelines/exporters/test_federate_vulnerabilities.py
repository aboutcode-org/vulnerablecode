#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import tempfile
from datetime import datetime
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.test import TestCase
from git import Repo
from packageurl import PackageURL
from univers.version_range import VersionRange

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.pipelines import insert_advisory_v2
from vulnerabilities.pipelines.exporters.federate_vulnerabilities import (
    FederatePackageVulnerabilities,
)
from vulnerabilities.tests import util_tests
from vulnerabilities.tests.pipelines import TestLogger

TEST_DATA = (
    Path(__file__).parent.parent.parent / "test_data" / "exporters" / "federate_vulnerabilities"
)


class TestFederatePackageVulnerabilities(TestCase):
    def setUp(self):
        self.logger = TestLogger()

        advisory = AdvisoryDataV2(
            summary="Test advisory",
            aliases=["CVE-2025-0001"],
            references=[],
            severities=[],
            weaknesses=[],
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL.from_string("pkg:npm/foobar"),
                    affected_version_range=VersionRange.from_string("vers:npm/<=1.2.3"),
                    fixed_version_range=VersionRange.from_string("vers:npm/1.2.4"),
                    introduced_by_commit_patches=[],
                    fixed_by_commit_patches=[],
                ),
                AffectedPackageV2(
                    package=PackageURL.from_string("pkg:npm/foobar"),
                    affected_version_range=VersionRange.from_string("vers:npm/<=3.2.3"),
                    fixed_version_range=VersionRange.from_string("vers:npm/3.2.4"),
                    introduced_by_commit_patches=[],
                    fixed_by_commit_patches=[],
                ),
            ],
            patches=[],
            advisory_id="ADV-123",
            date_published=datetime.now() - timedelta(days=10),
            url="https://example.com/advisory/1",
        )
        insert_advisory_v2(
            advisory=advisory,
            pipeline_id="test_pipeline_v2",
        )

    @patch(
        "vulnerabilities.pipelines.exporters.federate_vulnerabilities.FederatePackageVulnerabilities.clone_vulnerabilities_repo"
    )
    @patch("vulnerabilities.pipes.federatedcode.commit_and_push_changes")
    @patch("vulnerabilities.pipes.federatedcode.check_federatedcode_configured_and_available")
    def test_vulnerabilities_federation_v2(self, mock_check_fed, mock_commit, mock_clone):
        mock_check_fed.return_value = None
        mock_commit.return_value = None
        mock_clone.__name__ = "clone_vulnerabilities_repo"

        working_dir = Path(tempfile.mkdtemp())
        print(working_dir)

        pipeline = FederatePackageVulnerabilities()
        pipeline.repo = Repo.init(working_dir)
        pipeline.log = self.logger.write
        pipeline.execute()
        print(self.logger.getvalue())

        result_purl_yml = next(working_dir.rglob("purls.yml"))
        result_vulnerabilities_yml = next(working_dir.rglob("vulnerabilities.yml"))
        result_advisory_yml = next(working_dir.rglob("ADV-123.yml"))

        expected_purl_yml = TEST_DATA / "purls-expected.yml"
        expected_vulnerabilities_yml = TEST_DATA / "vulnerabilities-expected.yml"
        expected_advisory_yml = TEST_DATA / "ADV-123-expected.yml"

        util_tests.check_results_and_expected_files(result_purl_yml, expected_purl_yml)
        util_tests.check_results_and_expected_files(
            result_vulnerabilities_yml, expected_vulnerabilities_yml
        )
        util_tests.check_results_and_expected_files(result_advisory_yml, expected_advisory_yml)
