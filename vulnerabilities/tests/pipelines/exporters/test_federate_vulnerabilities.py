#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import json
import shutil
import tempfile
from datetime import datetime
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import saneyaml
from django.test import TestCase
from django.utils import timezone
from git import Repo
from jsonschema import Draft7Validator
from packageurl import PackageURL
from univers.version_range import VersionRange

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import PackageCommitPatchData
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import insert_advisory_v2
from vulnerabilities.pipelines.exporters.federate_vulnerabilities import (
    FederatePackageVulnerabilities,
)
from vulnerabilities.tests import util_tests
from vulnerabilities.tests.pipelines import TestLogger

TEST_DATA = (
    Path(__file__).parent.parent.parent / "test_data" / "exporters" / "federate_vulnerabilities"
)

LATEST_FEDERATEDCODE_ADVISORY_SCHEMA = (
    Path(__file__).parent.parent.parent.parent.parent
    / "docs"
    / "source"
    / "schemas"
    / "vulnerablecode-advisory.schema-0.1.json"
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
            references=[ReferenceV2(url="https://example.com/vuln1")],
            severities=[
                VulnerabilitySeverity(
                    system=severity_systems.CVSSV3,
                    scoring_elements="CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                    value="8.8",
                ),
            ],
            weaknesses=[707, 20],
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
        a1 = insert_advisory_v2(
            advisory=advisory1,
            pipeline_id="test_pipeline_v2",
            logger=self.logger.write,
            datasource_id="test",
        )
        cur = timezone.now()
        a1._all_impacts_unfurled_at = cur
        a1._all_impacts_unfurled_successfully_at = cur
        a1.save()
        a2 = insert_advisory_v2(
            advisory=advisory2,
            pipeline_id="test_pipeline_v2",
            logger=self.logger.write,
            datasource_id="test",
        )
        a2._all_impacts_unfurled_at = cur
        a2._all_impacts_unfurled_successfully_at = cur
        a2.save()

        self.working_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        if self.working_dir:
            shutil.rmtree(self.working_dir)

    @patch(
        "vulnerabilities.pipelines.exporters.federate_vulnerabilities.FederatePackageVulnerabilities.clone_federation_repository"
    )
    @patch("vulnerabilities.pipes.federatedcode.commit_and_push_changes")
    @patch("vulnerabilities.pipes.federatedcode.check_federatedcode_configured_and_available")
    def test_vulnerabilities_federation_v2(self, mock_check_fed, mock_commit, mock_clone):
        mock_check_fed.return_value = None
        mock_commit.return_value = None
        mock_clone.__name__ = "clone_federation_repository"

        pipeline = FederatePackageVulnerabilities()
        pipeline.repo = Repo.init(self.working_dir)
        pipeline.repo_path = self.working_dir
        pipeline.log = self.logger.write
        exit_code, _ = pipeline.execute()

        self.assertEqual(exit_code, 0)

        result_advisories_yml = next(self.working_dir.rglob("1.2.4/advisories.yml"))
        result_advisory1_yml = next(self.working_dir.rglob("ADV-001.yml"))
        result_advisory2_yml = next(self.working_dir.rglob("ADV-002.yml"))

        expected_advisories_yml = TEST_DATA / "1.2.4" / "advisories-expected.yml"
        expected_advisory1_yml = TEST_DATA / "ADV-001-expected.yml"
        expected_advisory2_yml = TEST_DATA / "ADV-002-expected.yml"

        util_tests.check_results_and_expected_files(result_advisories_yml, expected_advisories_yml)
        util_tests.check_results_and_expected_files(result_advisory1_yml, expected_advisory1_yml)
        util_tests.check_results_and_expected_files(result_advisory2_yml, expected_advisory2_yml)

    @patch(
        "vulnerabilities.pipelines.exporters.federate_vulnerabilities.FederatePackageVulnerabilities.clone_federation_repository"
    )
    @patch("vulnerabilities.pipes.federatedcode.commit_and_push_changes")
    @patch("vulnerabilities.pipes.federatedcode.check_federatedcode_configured_and_available")
    def test_vulnerabilities_federation_schema(self, mock_check_fed, mock_commit, mock_clone):
        mock_check_fed.return_value = None
        mock_commit.return_value = None
        mock_clone.__name__ = "clone_federation_repository"

        pipeline = FederatePackageVulnerabilities()
        pipeline.repo = Repo.init(self.working_dir)
        pipeline.repo_path = self.working_dir
        pipeline.log = self.logger.write
        exit_code, _ = pipeline.execute()

        self.assertEqual(exit_code, 0)

        with LATEST_FEDERATEDCODE_ADVISORY_SCHEMA.open("r", encoding="utf-8") as f:
            validator = Draft7Validator(json.load(f))

        result_advisory1_yml = saneyaml.load(
            next(self.working_dir.rglob("ADV-001.yml")).read_text(encoding="utf-8")
        )
        result_advisory2_yml = saneyaml.load(
            next(self.working_dir.rglob("ADV-002.yml")).read_text(encoding="utf-8")
        )

        validator.validate(result_advisory1_yml)
        validator.validate(result_advisory2_yml)
