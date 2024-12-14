#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
from pathlib import Path
from unittest import mock

import pytest

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.improvers.valid_versions import GitLabBasicImprover
from vulnerabilities.pipelines import gitlab_importer
from vulnerabilities.tests import util_tests
from vulnerabilities.tests.pipelines import TestLogger

TEST_DATA = Path(__file__).parent.parent / "test_data" / "gitlab"


@pytest.mark.parametrize("pkg_type", ["maven", "nuget", "gem", "composer", "pypi", "npm"])
def test_parse_yaml_file(pkg_type):
    response_file = TEST_DATA / f"{pkg_type}.yaml"
    expected_file = TEST_DATA / f"{pkg_type}-expected.json"
    test_pipeline = gitlab_importer.GitLabImporterPipeline()
    logger = TestLogger()
    advisory = gitlab_importer.parse_gitlab_advisory(
        response_file,
        response_file.parent,
        test_pipeline.gitlab_scheme_by_purl_type,
        test_pipeline.purl_type_by_gitlab_scheme,
        logger.write,
    )
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
        "gem": ["4.2.0.beta1", "4.2.0.beta2", "4.2.0.beta3"],
        "golang": ["3.7.0", "3.7.1"],
        "nuget": ["1.11.0", "1.11.1", "1.11.2", "1.09.1"],
        "npm": ["2.14.2", "2.13.2", "2.11.2"],
        "pypi": ["1.0", "0.9", "0.8", "1.1"],
        "composer": [],
    }
    return valid_versions_by_package_type[pkg_type]


@mock.patch("vulnerabilities.improvers.valid_versions.GitLabBasicImprover.get_package_versions")
@pytest.mark.parametrize("pkg_type", ["maven", "nuget", "gem", "composer", "pypi", "npm"])
def test_gitlab_improver(mock_response, pkg_type):
    advisory_file = TEST_DATA / f"{pkg_type}-expected.json"
    expected_file = TEST_DATA / f"{pkg_type}-improver-expected.json"
    with advisory_file.open() as exp:
        advisory = AdvisoryData.from_dict(json.load(exp))
    mock_response.return_value = list(valid_versions(pkg_type))
    improvers = [GitLabBasicImprover(), DefaultImprover()]
    result = []
    for improver in improvers:
        inference = [data.to_dict() for data in improver.get_inferences(advisory)]
        result.extend(inference)
    util_tests.check_results_against_json(result, expected_file)
