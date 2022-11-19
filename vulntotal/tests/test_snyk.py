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
from vulntotal.datasources import snyk


class TestSnyk(testcase.FileBasedTesting):
    test_data_dir = str(Path(__file__).resolve().parent / "test_data" / "snyk")

    def test_generate_package_advisory_url(self):
        file_purls = self.get_test_loc("purls.txt")
        with open(file_purls) as f:
            purls = f.readlines()
        results = [
            snyk.generate_package_advisory_url(PackageURL.from_string(purl)) for purl in purls
        ]
        expected_file = self.get_test_loc("package_advisory_url-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)

    def test_extract_html_json_advisories(self):
        file = self.get_test_loc("raw_pacakage_advisories.json")
        with open(file) as f:
            pages = json.load(f)
        results = [snyk.extract_html_json_advisories(i) for i in pages]
        expected_file = self.get_test_loc("extract_html_json-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)

    def test_parse_html_advisory(self):
        file = self.get_test_loc("raw_html_advisory.json")
        with open(file) as f:
            pages = json.load(f)
        results = [
            snyk.parse_html_advisory(i, "TEST-SNYKID", ["TEST-AFFECTED"]).to_dict() for i in pages
        ]
        expected_file = self.get_test_loc("parsed_advisory-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)
