#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path

from commoncode import testcase
from packageurl import PackageURL

from vulnerabilities.tests import util_tests
from vulntotal.datasources import gitlab


class TestGitlab(testcase.FileBasedTesting):
    test_data_dir = str(Path(__file__).resolve().parent / "test_data" / "gitlab")

    def test_generate_package_advisory_url(self):
        file_purls = self.get_test_loc("purls.txt")
        with open(file_purls) as f:
            purls = f.readlines()
        results = [gitlab.get_package_slug(PackageURL.from_string(purl)) for purl in purls]
        expected_file = self.get_test_loc("package_advisory_url-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)

    def test_parse_html_advisory(self):
        advisory_folder = (
            Path(__file__)
            .resolve()
            .parent.joinpath("test_data/gitlab/temp_vulntotal_gitlab_datasource")
        )
        results = [
            adv.to_dict()
            for adv in gitlab.parse_interesting_advisories(advisory_folder, "0.1.1", False)
        ]
        expected_file = self.get_test_loc("parsed_advisory-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)
