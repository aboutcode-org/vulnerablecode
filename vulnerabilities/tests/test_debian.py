#
# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import json
import os
from unittest.mock import patch

from vulnerabilities.importers.debian import DebianBasicImprover
from vulnerabilities.importers.debian import DebianImporter
from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data")


@patch("vulnerabilities.importers.debian.DebianImporter.get_response")
def test_debian_importer(mock_response):
    with open(os.path.join(TEST_DATA, "debian.json")) as f:
        mock_response.return_value = json.load(f)

    expected_file = os.path.join(TEST_DATA, f"debian-expected.json")
    result = [data.to_dict() for data in list(DebianImporter().advisory_data())]
    util_tests.check_results_against_json(result, expected_file)


@patch("vulnerabilities.importers.debian.DebianImporter.get_response")
def test_debian_improver(mock_response):
    with open(os.path.join(TEST_DATA, "debian.json")) as f:
        mock_response.return_value = json.load(f)
    advisories = list(DebianImporter().advisory_data())
    result = []
    improvers = [DebianBasicImprover(), DefaultImprover()]
    for improver in improvers:
        for advisory in advisories:
            for data in improver.get_inferences(advisory_data=advisory):
                result.append(data.to_dict())
    expected_file = os.path.join(TEST_DATA, f"debian-improver-expected.json")
    util_tests.check_results_against_json(result, expected_file)
