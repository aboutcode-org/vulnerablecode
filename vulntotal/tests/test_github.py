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
from vulntotal.datasources import github


class TestGithub(testcase.FileBasedTesting):
    test_data_dir = str(Path(__file__).resolve().parent / "test_data" / "github")

    def test_generate_graphql_payload(self):
        purls = [
            "pkg:pypi/jinja2@2.4.1",
            "pkg:maven/org.apache.tomcat/tomcat@10.1.0-M8",
            "pkg:nuget/moment.js@2.18.0",
            "pkg:npm/semver-regex@3.1.3",
            "pkg:golang/github.com/cloudflare/cfrpki@0.1.0",
            "pkg:composer/symfony/symfony@2.7.1",
            "pkg:rust/slice-deque@0.1.0",
            "pkg:erlang/alchemist.vim@1.3.0",
            "pkg:gem/ftpd@0.0.1",
        ]
        results = [
            github.generate_graphql_payload(PackageURL.from_string(purl), "") for purl in purls
        ]
        expected_file = self.get_test_loc("graphql_payload-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)

    def test_extract_interesting_edge(self):
        file = self.get_test_loc("all_edges.json")
        with open(file) as f:
            edges = json.load(f)
        results = github.extract_interesting_edge(
            edges["edges"], PackageURL.from_string("pkg:pypi/jinja2@2.4.1")
        )
        expected_file = self.get_test_loc(
            "extracted_interesting_edge-expected.json", must_exist=False
        )
        util_tests.check_results_against_json(results, expected_file)

    def test_parse_advisory(self):
        advisory_file = self.get_test_loc("interesting_edge.json")
        with open(advisory_file) as f:
            advisory = json.load(f)
        results = [adv.to_dict() for adv in github.parse_advisory(advisory)]
        expected_file = self.get_test_loc("parse_advisory-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)
