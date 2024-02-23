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
from unittest import TestCase

from vulnerabilities.importers.osv import parse_advisory_data
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/github_osv")


class GithubOSVImporter(TestCase):
    def test_github_osv_importer1(self):
        with open(os.path.join(TEST_DATA, "github_osv_test_1.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "github_osv_expected_1.json")
        imported_data = parse_advisory_data(
            mock_response,
            supported_ecosystems=["npm"],
            advisory_url="https://github.com/github/advisory-database"
            "/blob/main/advisories/github-reviewed/github_osv_test_1.json",
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_github_osv_importer2(self):
        with open(os.path.join(TEST_DATA, "github_osv_test_2.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "github_osv_expected_2.json")
        # if supported_ecosystems = [] : the expected affected_packages = []
        imported_data = parse_advisory_data(
            mock_response,
            supported_ecosystems=[],
            advisory_url="https://github.com/github/advisory-database"
            "/blob/main/advisories/github-reviewed/github_osv_test_2.json",
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_github_osv_importer3(self):
        with open(os.path.join(TEST_DATA, "github_osv_test_3.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "github_osv_expected_3.json")
        imported_data = parse_advisory_data(
            mock_response,
            supported_ecosystems=["maven"],
            advisory_url="https://github.com/github/advisory-database"
            "/blob/main/advisories/github-reviewed/github_osv_test_3.json",
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_github_osv_importer4(self):
        with open(os.path.join(TEST_DATA, "github_osv_test_4.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "github_osv_expected_4.json")
        imported_data = parse_advisory_data(
            mock_response,
            supported_ecosystems=["gem"],
            advisory_url="https://github.com/github/advisory-database"
            "/blob/main/advisories/github-reviewed/github_osv_test_4.json",
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_github_osv_importer5(self):
        # test golang
        with open(os.path.join(TEST_DATA, "github_osv_test_5.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "github_osv_expected_5.json")
        imported_data = parse_advisory_data(
            mock_response,
            supported_ecosystems=["golang"],
            advisory_url="https://github.com/github/advisory-database"
            "/blob/main/advisories/github-reviewed/github_osv_test_5.json",
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_github_osv_importer6(self):
        # test golang
        with open(os.path.join(TEST_DATA, "github_osv_test_6.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "github_osv_expected_6.json")
        imported_data = parse_advisory_data(
            mock_response,
            supported_ecosystems=["golang"],
            advisory_url="https://github.com/github/advisory-database"
            "/blob/main/advisories/github-reviewed/github_osv_test_6.json",
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_github_osv_importer7(self):
        with open(os.path.join(TEST_DATA, "github_osv_test_7.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "github_osv_expected_7.json")
        imported_data = parse_advisory_data(
            mock_response,
            supported_ecosystems=["nuget"],
            advisory_url="https://github.com/github/advisory-database"
            "/blob/main/advisories/github-reviewed/github_osv_test_7.json",
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)
