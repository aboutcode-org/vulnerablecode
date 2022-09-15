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
from vulntotal.datasources import osv


class TestOSV(testcase.FileBasedTesting):
    test_data_dir = str(Path(__file__).resolve().parent / "test_data" / "osv")

    def test_generate_payload(self):
        file_purls = self.get_test_loc("purls.txt")
        with open(file_purls) as f:
            purls = f.readlines()
        results = [osv.generate_payload(PackageURL.from_string(purl)) for purl in purls]
        expected_file = self.get_test_loc("payloads_data-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)

    def test_parse_advisory(self):
        advisory_page = self.get_test_loc("advisory.txt")
        with open(advisory_page) as f:
            advisory = json.load(f)
        results = [adv.to_dict() for adv in osv.parse_advisory(advisory)]
        expected_file = self.get_test_loc("parse_advisory_data-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)
