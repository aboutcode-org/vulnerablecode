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
from vulntotal.datasources import deps


class TestDeps(testcase.FileBasedTesting):
    test_data_dir = str(Path(__file__).resolve().parent / "test_data" / "deps")

    def test_generate_meta_payload(self):
        purls = [
            "pkg:pypi/jinja2@2.4.1",
            "pkg:maven/org.apache.tomcat/tomcat@10.1.0-M8",
            "pkg:npm/semver-regex@3.1.3",
            "pkg:golang/github.com/cloudflare/cfrpki@1.4.1",
            "pkg:cargo/rand@0.5.4",
        ]

        results = [deps.generate_meta_payload(PackageURL.from_string(purl)) for purl in purls]
        expected_file = self.get_test_loc("payloads_meta-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)

    def test_parse_advisory_from_meta(self):
        file = self.get_test_loc("advisories_metadata.txt")
        with open(file) as f:
            metadata = json.load(f)
        results = deps.parse_advisories_from_meta(metadata)
        expected_file = self.get_test_loc(
            "parsed_advisories_metadata-expected.json", must_exist=False
        )
        util_tests.check_results_against_json(results, expected_file)

    def test_generate_advisory_payload(self):
        file = self.get_test_loc("advisories_metadata.json")
        with open(file) as f:
            advisories = json.load(f)
        results = [deps.generate_advisory_payload(adv) for adv in advisories]
        expected_file = self.get_test_loc("payloads_advisories-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)

    def test_parse_advisory(self):
        advisory_file = self.get_test_loc("advisory.json")
        with open(advisory_file) as f:
            advisory = json.load(f)
        results = [adv.to_dict() for adv in deps.parse_advisory(advisory)]
        expected_file = self.get_test_loc("parse_advisory-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)
