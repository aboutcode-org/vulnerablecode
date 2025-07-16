#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os
from pathlib import Path
from unittest.mock import Mock
from unittest.mock import patch

from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importers.elixir_security import ElixirSecurityImporter
from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.improvers.valid_versions import ElixirImprover
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DIR = os.path.join(BASE_DIR, "test_data/elixir_security/")


def test_elixir_process_file():
    path = os.path.join(TEST_DIR, "test_file.yml")
    expected_file = os.path.join(TEST_DIR, f"elixir-expected.json")
    result = [
        data.to_dict()
        for data in list(ElixirSecurityImporter().process_file(Path(path), Path(path).parent))
    ]
    util_tests.check_results_against_json(result, expected_file)


@patch("vulnerabilities.improvers.valid_versions.ElixirImprover.get_package_versions")
def test_elixir_improver(mock_response):
    advisory_file = os.path.join(TEST_DIR, f"elixir-expected.json")
    with open(advisory_file) as exp:
        advisories = [AdvisoryData.from_dict(adv) for adv in (json.load(exp))]
    mock_response.return_value = [
        "0.1.0",
        "0.5.6",
        "0.5.2",
        "1.1.0",
        "1.1.1",
        "1.1.2",
        "1.1.3",
        "1.1.4",
        "1.1.5",
        "1.1.6",
        "1.1.7",
        "1.1.8",
    ]
    improvers = [ElixirImprover(), DefaultImprover()]
    result = []
    for improver in improvers:
        for advisory in advisories:
            inference = [data.to_dict() for data in improver.get_inferences(advisory)]
            result.extend(inference)
    expected_file = os.path.join(TEST_DIR, f"elixir-improver-expected.json")
    util_tests.check_results_against_json(result, expected_file)


@patch("requests.get")
def test_elixir_package_first_mode_success(mock_get):
    directory_response = Mock()
    directory_response.status_code = 200
    directory_response.json.return_value = [
        {"name": "test_file.yml", "path": "packages/coherence/test_file.yml"}
    ]

    test_file_path = os.path.join(TEST_DIR, "test_file.yml")
    with open(test_file_path, "r") as f:
        test_content = f.read()

    content_response = Mock()
    content_response.status_code = 200
    content_response.text = test_content

    mock_get.side_effect = [directory_response, content_response]

    purl = PackageURL(type="hex", name="coherence")
    importer = ElixirSecurityImporter(purl=purl)

    advisories = list(importer.advisory_data())

    assert len(advisories) == 1
    advisory = advisories[0]
    assert "CVE-2018-20301" in advisory.aliases
    assert advisory.summary == 'The Coherence library has "Mass Assignment"-like vulnerabilities.'
    assert len(advisory.affected_packages) == 1
    assert advisory.affected_packages[0].package.name == "coherence"


@patch("requests.get")
def test_elixir_package_first_mode_with_version_filter(mock_get):
    directory_response = Mock()
    directory_response.status_code = 200
    directory_response.json.return_value = [
        {"name": "test_file.yml", "path": "packages/coherence/test_file.yml"}
    ]

    test_file_path = os.path.join(TEST_DIR, "test_file.yml")
    with open(test_file_path, "r") as f:
        test_content = f.read()

    content_response = Mock()
    content_response.status_code = 200
    content_response.text = test_content

    mock_get.side_effect = [directory_response, content_response]

    purl = PackageURL(type="hex", name="coherence", version="0.5.1")
    importer = ElixirSecurityImporter(purl=purl)
    advisories = list(importer.advisory_data())
    assert len(advisories) == 1

    mock_get.side_effect = [directory_response, content_response]
    purl = PackageURL(type="hex", name="coherence", version="0.5.2")
    importer = ElixirSecurityImporter(purl=purl)
    advisories = list(importer.advisory_data())
    assert len(advisories) == 0


@patch("requests.get")
def test_elixir_package_first_mode_no_advisories(mock_get):
    mock_response = Mock()
    mock_response.status_code = 404
    mock_get.return_value = mock_response

    purl = PackageURL(type="hex", name="nonexistent-package")
    importer = ElixirSecurityImporter(purl=purl)

    advisories = list(importer.advisory_data())
    assert len(advisories) == 0


@patch("requests.get")
def test_elixir_package_first_mode_api_error(mock_get):
    directory_response = Mock()
    directory_response.status_code = 200
    directory_response.json.return_value = [
        {"name": "test_file.yml", "path": "packages/coherence/test_file.yml"}
    ]

    content_response = Mock()
    content_response.status_code = 500

    mock_get.side_effect = [directory_response, content_response]

    purl = PackageURL(type="hex", name="coherence")
    importer = ElixirSecurityImporter(purl=purl)

    advisories = list(importer.advisory_data())
    assert len(advisories) == 0


def test_elixir_package_first_mode_non_hex_purl():
    purl = PackageURL(type="npm", name="some-package")
    importer = ElixirSecurityImporter(purl=purl)

    advisories = list(importer.advisory_data())
    assert len(advisories) == 0
