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

from commoncode import testcase
from packageurl import PackageURL

from vulnerabilities.tests import util_tests
from vulntotal.datasources import safetydb


class TestSafetydb(testcase.FileBasedTesting):
    test_data_dir = str(Path(__file__).resolve().parent / "test_data" / "safetydb")

    def test_parse_advisory(self):
        purl = PackageURL.from_string("pkg:pypi/flask")
        advisory_file = self.get_test_loc("advisory.json")
        with open(advisory_file) as f:
            advisory = json.load(f)

        results = [adv.to_dict() for adv in safetydb.parse_advisory(advisory, purl)]
        expected_file = self.get_test_loc("parse_advisory-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)

    def test_parse_advisory_for_cve(self):
        cve = "CVE-2019-1010083"
        advisory_file = self.get_test_loc("advisory.json")
        with open(advisory_file) as f:
            advisory = json.load(f)

        results = [adv.to_dict() for adv in safetydb.parse_advisory_for_cve(advisory, cve)]
        expected_file = self.get_test_loc("parse_advisory_cve-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)
