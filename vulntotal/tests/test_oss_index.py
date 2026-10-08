#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
from pathlib import Path
from unittest.mock import patch

from commoncode import testcase
from packageurl import PackageURL

from vulnerabilities.tests import util_tests
from vulntotal.datasources import oss_index


class TestDeps(testcase.FileBasedTesting):
    test_data_dir = str(Path(__file__).resolve().parent / "test_data" / "oss_index")

    def test_fetch_json_response_uses_sonatype_guide_compatibility_api(self):
        coordinates = ["pkg:pypi/django@5.2.1"]
        datasource = oss_index.OSSDataSource()

        with patch.object(oss_index.requests, "post") as mock_post:
            mock_response = mock_post.return_value
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = []

            assert datasource.fetch_json_response(coordinates) == []

        mock_post.assert_called_once_with(
            "https://api.guide.sonatype.com/api/v3/component-report",
            auth=None,
            json={"coordinates": coordinates},
        )

    def test_fetch_json_response_uses_authenticated_sonatype_guide_compatibility_api(self):
        coordinates = ["pkg:pypi/django@5.2.1"]
        datasource = oss_index.OSSDataSource()

        with patch.dict(oss_index.os.environ, {"OSS_USERNAME": "user", "OSS_TOKEN": "token"}):
            with patch.object(oss_index.requests, "post") as mock_post:
                mock_response = mock_post.return_value
                mock_response.raise_for_status.return_value = None
                mock_response.json.return_value = []

                assert datasource.fetch_json_response(coordinates) == []

        mock_post.assert_called_once_with(
            "https://api.guide.sonatype.com/api/v3/authorized/component-report",
            auth=("user", "token"),
            json={"coordinates": coordinates},
        )

    def test_parse_advisory(self):
        advisory_file = self.get_test_loc("advisory.json")
        with open(advisory_file) as f:
            advisory = json.load(f)
        results = [
            adv.to_dict()
            for adv in oss_index.parse_advisory(
                advisory, PackageURL("generic", "namespace", "test")
            )
        ]
        expected_file = self.get_test_loc("parse_advisory-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)
