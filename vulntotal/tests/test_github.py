#
# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnTotal software is licensed under the Apache License version 2.0.
# Data generated with VulnTotal require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnTotal or any VulnTotal
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnTotal and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnTotal should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnTotal is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import json
from pathlib import Path

from commoncode import testcase
from packageurl import PackageURL

from vulnerabilities.tests import util_tests
from vulntotal.datasources import github


class TestGithub(testcase.FileBasedTesting):
    test_data_dir = str(Path(__file__).resolve().parent / "test_data" / "github")

    def test_generate_graphql_payload(self):
        file_purls = self.get_test_loc("purls.txt")
        with open(file_purls) as f:
            purls = f.readlines()
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
