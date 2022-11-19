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
