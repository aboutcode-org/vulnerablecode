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
#  VulnerableCode is a free software code from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import json
import os
from unittest.mock import patch

from packageurl import PackageURL

from vulnerabilities.importers import redhat
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "redhat")


def test_rpm_to_purl():
    assert redhat.rpm_to_purl("foobar", "redhat") is None
    assert redhat.rpm_to_purl("foo-bar-devel-0:sys76", "redhat") is None
    assert redhat.rpm_to_purl("kernel-0:2.6.32-754.el6", "redhat") == PackageURL(
        type="rpm",
        namespace="redhat",
        name="kernel",
        version="2.6.32-754",
        qualifiers={"arch": "el6"},
    )


@patch("vulnerabilities.importers.redhat.fetch_list_of_cves")
@patch("vulnerabilities.importers.redhat.get_data_from_url")
def test_redhat_importer(get_data_from_url, fetcher, caplog):
    redhat_importer = redhat.RedhatImporter()
    response_file = os.path.join(TEST_DATA, f"redhat-input.json")

    with open(response_file) as f:
        fetcher.return_value = [json.load(f)]
    bugzilla_2075788_response_file = os.path.join(TEST_DATA, f"bugzilla-2075788.json")
    bugzilla_2077736_response_file = os.path.join(TEST_DATA, f"bugzilla-2077736.json")
    rhsa_1437 = os.path.join(TEST_DATA, f"RHSA-2022:1437.json")
    rhsa_1439 = os.path.join(TEST_DATA, f"RHSA-2022:1439.json")
    get_data_from_url.side_effect = [
        json.load(open(bugzilla_2075788_response_file)),
        json.load(open(bugzilla_2077736_response_file)),
        json.load(open(rhsa_1439)),
        json.load(open(rhsa_1437)),
        None,
    ]
    expected_file = os.path.join(TEST_DATA, f"redhat-expected.json")
    imported_data = list(redhat_importer.advisory_data())
    result = [data.to_dict() for data in imported_data]
    util_tests.check_results_against_json(result, expected_file)
