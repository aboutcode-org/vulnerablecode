#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from datetime import datetime
from datetime import timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

import pytest

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import CodeFixV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines.v2_importers.project_kb_importer import ProjectKBPipeline
from vulnerabilities.pipelines.v2_improvers.collect_commits_project_kb import (
    CollectFixCommitsProjectKBPipeline,
)
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "kbmsr2019"


class TestProjectKbImporterPipeline(TestCase):
    """
    Integration-style test that validates YAML → Advisory → JSON conversion
    using real test data files, but mocks network and repo access.
    """

    @patch(
        "vulnerabilities.pipelines.v2_importers.project_kb_importer.get_advisory_url",
        return_value="https://mocked.url/advisory",
    )
    def test_project_kb_collect_advisories_v2(self, mock_get_advisory_url):
        pipeline = ProjectKBPipeline()
        pipeline.vcs_response = SimpleNamespace(dest_dir=TEST_DATA)

        for idx in range(1, 4):
            yaml_file = TEST_DATA / str(idx) / f"statement.yaml"
            expected_file = TEST_DATA / f"statement-{idx}-expected.json"

            with patch(
                "vulnerabilities.pipelines.v2_importers.project_kb_importer.Path.rglob",
                return_value=[yaml_file],
            ):
                result = [adv.to_dict() for adv in pipeline.collect_advisories()]

            util_tests.check_results_against_json(result, expected_file)

    @pytest.mark.django_db
    def test_collect_fix_commits_uses_existing_csv(self):
        """
        Test that CollectFixCommitsProjectKBPipeline.collect_fix_commits()
        reads an existing ProjectKB CSV file and creates CodeFixV2 entries.
        """

        advisory = AdvisoryV2.objects.create(
            advisory_id="CVE-2018-8034",
            datasource_id="test-datasource",
            avid="TEST-1234",
            unique_content_id="unique-test-id",
            url="https://example.com/advisory/CVE-2018-8034",
            date_collected=datetime.now(timezone.utc),
        )

        pkg1 = PackageV2.objects.create(name="test_name1", type="test")
        pkg2 = PackageV2.objects.create(name="test_name2", type="test")

        impacted = ImpactedPackage.objects.create(advisory=advisory)
        impacted.affecting_packages.set([pkg1, pkg2])

        pipeline = CollectFixCommitsProjectKBPipeline()
        pipeline.vcs_response = SimpleNamespace(dest_dir=TEST_DATA)

        pipeline.collect_fix_commits()

        fixes = CodeFixV2.objects.all()
        assert len(fixes) == 2
        assert [fix.commits for fix in fixes] == [
            ["https://github.com/apache/tomcat/commit/2835bb4e030c1c741ed0847bb3b9c3822e4fbc8a"],
            ["https://github.com/apache/tomcat/commit/2835bb4e030c1c741ed0847bb3b9c3822e4fbc8a"],
        ]
