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
from vulnerabilities.importer import PackageCommitPatchData
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

        advisory1 = AdvisoryDataV2(
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
            ],
            patches=[],
            advisory_id="ADV-001",
            date_published=datetime.now() - timedelta(days=10),
            url="https://example.com/advisory/1",
        )
        advisory2 = AdvisoryDataV2(
            summary="Test advisory2",
            aliases=["CVE-2025-0002"],
            references=[],
            severities=[],
            weaknesses=[],
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL.from_string("pkg:npm/foobar"),
                    affected_version_range=VersionRange.from_string("vers:npm/>=1.2.4"),
                    fixed_version_range=VersionRange.from_string("vers:npm/2.0.0"),
                    fixed_by_commit_patches=[
                        PackageCommitPatchData(
                            vcs_url="https://foobar.vcs/",
                            commit_hash="982f801f",
                        )
                    ],
                    introduced_by_commit_patches=[],
                ),
            ],
            patches=[],
            advisory_id="ADV-002",
            date_published=datetime.now() - timedelta(days=10),
            url="https://example.com/advisory/2",
        )
        insert_advisory_v2(
            advisory=advisory1,
            pipeline_id="test_pipeline_v2",
            logger=self.logger.write,
        )
        insert_advisory_v2(
            advisory=advisory2,
            pipeline_id="test_pipeline_v2",
            logger=self.logger.write,
        )

    @patch(
        "vulnerabilities.pipelines.exporters.federate_vulnerabilities.FederatePackageVulnerabilities.clone_federation_repository"
    )
    @patch("vulnerabilities.pipes.federatedcode.commit_and_push_changes")
    @patch("vulnerabilities.pipes.federatedcode.check_federatedcode_configured_and_available")
    def test_vulnerabilities_federation_v2(self, mock_check_fed, mock_commit, mock_clone):
        mock_check_fed.return_value = None
        mock_commit.return_value = None
        mock_clone.__name__ = "clone_federation_repository"

        working_dir = Path(tempfile.mkdtemp())
        pipeline = FederatePackageVulnerabilities()
        pipeline.repo = Repo.init(working_dir)
        pipeline.repo_path = working_dir
        pipeline.log = self.logger.write
        exit_code, _ = pipeline.execute()

        self.assertEqual(exit_code, 0)

        result_advisories_yml = next(working_dir.rglob("1.2.4/advisories.yml"))
        result_advisory1_yml = next(working_dir.rglob("ADV-001.yml"))
        result_advisory2_yml = next(working_dir.rglob("ADV-002.yml"))

        expected_advisories_yml = TEST_DATA / "1.2.4" / "advisories-expected.yml"
        expected_advisory1_yml = TEST_DATA / "ADV-001-expected.yml"
        expected_advisory2_yml = TEST_DATA / "ADV-002-expected.yml"

        util_tests.check_results_and_expected_files(result_advisories_yml, expected_advisories_yml)
        util_tests.check_results_and_expected_files(result_advisory1_yml, expected_advisory1_yml)
        util_tests.check_results_and_expected_files(result_advisory2_yml, expected_advisory2_yml)
