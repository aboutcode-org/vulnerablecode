#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os
from unittest import mock

import pytest

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importers.gitlab import GitLabBasicImprover
from vulnerabilities.importers.gitlab import parse_gitlab_advisory
from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "gitlab")


@pytest.mark.parametrize("pkg_type", ["maven", "nuget", "gem", "composer", "pypi", "npm"])
def test_parse_yaml_file(pkg_type):
    response_file = os.path.join(TEST_DATA, f"{pkg_type}.yaml")
    expected_file = os.path.join(TEST_DATA, f"{pkg_type}-expected.json")
    advisory = parse_gitlab_advisory(response_file)
    util_tests.check_results_against_json(advisory.to_dict(), expected_file)


def valid_versions(pkg_type):
    valid_versions_by_package_type = {
        "maven": [
            "1.0.0",
            "1.0.1",
            "1.0.2",
            "2.0.4",
            "9.0.7",
            "2.0.5",
            "9.0.6",
            "9.1.6",
            "10.0.0",
        ],
        "gem": [
            "4.2.0.beta1",
            "4.2.0.beta2",
            "4.2.0.beta3",
        ],
        "golang": [
            "3.7.0",
            "3.7.1",
        ],
        "nuget": ["1.11.0", "1.11.1", "1.11.2", "1.09.1"],
        "npm": [
            "2.14.2",
            "2.13.2",
            "2.11.2",
        ],
        "pypi": [
            "1.0",
            "0.9",
            "0.8",
            "1.1",
        ],
        "composer": [],
    }
    return valid_versions_by_package_type[pkg_type]


@mock.patch("vulnerabilities.importers.gitlab.GitLabBasicImprover.get_package_versions")
@pytest.mark.parametrize("pkg_type", ["maven", "nuget", "gem", "composer", "pypi", "npm"])
def test_gitlab_improver(mock_response, pkg_type):
    advisory_file = os.path.join(TEST_DATA, f"{pkg_type}-expected.json")
    expected_file = os.path.join(TEST_DATA, f"{pkg_type}-improver-expected.json")
    with open(advisory_file) as exp:
        advisory = AdvisoryData.from_dict(json.load(exp))
    mock_response.return_value = list(valid_versions(pkg_type))
    improvers = [GitLabBasicImprover(), DefaultImprover()]
    result = []
    for improver in improvers:
        inference = [data.to_dict() for data in improver.get_inferences(advisory)]
        result.extend(inference)
    util_tests.check_results_against_json(result, expected_file)
