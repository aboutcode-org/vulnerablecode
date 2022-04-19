#
# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an 'AS IS' BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import json
import os

from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.improver import Inference
from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "default_improver")


def test_default_improver_with_no_data():
    """
    Test that DefaultImprover.get_inferences() returns an empty list when given no data
    """
    default_improver = DefaultImprover()
    result = list(default_improver.get_inferences(None))
    expected = []
    assert result == expected


def test_default_improver_with_empty_affected_packages():
    """
    Test that DefaultImprover.get_inferences() returns an empty list when given an advisory with no affected packages
    """
    advisory_data = AdvisoryData(
        aliases=["CVE-2020-1234"],
        summary="Test summary",
        references=[
            Reference(
                url="https://www.example.com/",
            )
        ],
        affected_packages=[],
    )
    default_improver = DefaultImprover()
    expected_inference = Inference(
        vulnerability_id=None,
        aliases=["CVE-2020-1234"],
        confidence=100,
        summary="Test summary",
        affected_purls=[],
        fixed_purl=None,
        references=[Reference(reference_id="", url="https://www.example.com/", severities=[])],
    )
    expected = [expected_inference]
    result = list(default_improver.get_inferences(advisory_data))
    assert result == expected


def test_default_improver_with_affected_packages():
    """
    Test that DefaultImprover.get_inferences() returns an empty list when given an advisory with no affected packages
    """
    advisory_data = AdvisoryData(
        aliases=["CVE-2020-1234"],
        summary="Test summary",
        references=[
            Reference(
                url="https://www.example.com/",
            )
        ],
        affected_packages=[
            AffectedPackage(
                package=PackageURL(
                    name="python",
                    namespace="rpms",
                    type="rpm",
                ),
                affected_version_range=None,
                fixed_version="3.7.0",
            )
        ],
    )
    default_improver = DefaultImprover()
    expected_inference = Inference(
        vulnerability_id=None,
        aliases=["CVE-2020-1234"],
        confidence=100,
        summary="Test summary",
        affected_purls=[],
        fixed_purl=PackageURL(
            type="rpm",
            namespace="rpms",
            name="python",
            version="3.7.0",
            qualifiers={},
            subpath=None,
        ),
        references=[Reference(reference_id="", url="https://www.example.com/", severities=[])],
    )
    result = list(default_improver.get_inferences(advisory_data))
    expected = [expected_inference]
    assert result == expected


def test_default_improver_with_alpine():
    """
    Test that DefaultImprover.get_inferences() returns an empty list when given an advisory with alpine advisories
    """
    default_improver = DefaultImprover()
    response_file = os.path.join(TEST_DATA, f"alpine-input.json")
    with open(response_file) as f:
        advisory_data = json.load(f)
    expected_file = os.path.join(TEST_DATA, f"alpine-expected.json")
    result = [
        data.to_dict()
        for data in list(default_improver.get_inferences(AdvisoryData.from_dict(advisory_data)))
    ]
    util_tests.check_results_against_json(result, expected_file)


def test_default_improver_with_nvd():
    default_improver = DefaultImprover()
    response_file = os.path.join(TEST_DATA, f"nvd-input.json")

    with open(response_file) as f:
        advisory_data = json.load(f)
    expected_file = os.path.join(TEST_DATA, f"nvd-expected.json")
    result = [
        data.to_dict()
        for data in list(default_improver.get_inferences(AdvisoryData.from_dict(advisory_data)))
    ]
    util_tests.check_results_against_json(result, expected_file)
