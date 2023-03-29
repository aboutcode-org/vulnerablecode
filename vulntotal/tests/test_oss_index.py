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
from vulntotal.datasources import oss_index


class TestDeps(testcase.FileBasedTesting):
    test_data_dir = str(Path(__file__).resolve().parent / "test_data" / "oss_index")

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
