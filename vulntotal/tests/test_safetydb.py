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
from fetchcode.package_versions import versions
from packageurl import PackageURL
from univers.version_range import PypiVersionRange
from univers.versions import PypiVersion

from vulnerabilities.tests import util_tests
from vulntotal.datasources import safetydb


class TestGithub(testcase.FileBasedTesting):
    test_data_dir = str(Path(__file__).resolve().parent / "test_data" / "safetydb")

    def test_parse_advisory(self):
        purl = PackageURL.from_string("pkg:pypi/flask")
        advisory_file = self.get_test_loc("advisory.json")
        with open(advisory_file) as f:
            advisory = json.load(f)
        all_versions = sorted([PypiVersion(ver.value) for ver in versions(str(purl))])

        results = [adv.to_dict() for adv in safetydb.parse_advisory(advisory, purl, all_versions)]
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

    def test_get_patched_versions(self):
        # Ref - flask package
        all_versions = [
            PypiVersion(ver)
            for ver in [
                "0.12.2",
                "0.12.3",
                "0.12.4",
                "0.12.5",
                "1.0",
                "2.2.4",
                "2.2.5",
                "2.3.0",
                "2.3.1",
                "2.3.2",
                "2.3.3",
                "3.0.0",
                "3.0.1",
                "3.0.2",
                "3.0.3",
            ]
        ]

        test_cases = [
            {
                "vulnerable_version_range": PypiVersionRange.from_string("vers:pypi/<0.12.3"),
                "expected_patched_version_ranges": ["0.12.3"],
            },
            {
                "vulnerable_version_range": PypiVersionRange.from_string(
                    "vers:pypi/<2.2.5|>=2.3.0|<2.3.2"
                ),
                "expected_patched_version_ranges": ["2.2.5", ">=2.3.2"],
            },
        ]

        for test_case in test_cases:
            results = safetydb.get_patched_versions(
                all_versions, test_case["vulnerable_version_range"]
            )
            util_tests.check_results_against_expected(
                results, test_case["expected_patched_version_ranges"]
            )
