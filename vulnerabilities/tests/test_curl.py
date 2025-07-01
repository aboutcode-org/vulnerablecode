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
from unittest import TestCase
from unittest.mock import patch

import pytest
from packageurl import PackageURL
from univers.versions import SemverVersion

from vulnerabilities.importers.curl import CurlImporter
from vulnerabilities.importers.curl import get_cwe_from_curl_advisory
from vulnerabilities.importers.curl import parse_advisory_data
from vulnerabilities.tests import util_tests
from vulnerabilities.utils import load_json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/curl")


class TestCurlImporter(TestCase):
    def test_parse_advisory_data1(self):
        mock_response = load_json(os.path.join(TEST_DATA, "curl_advisory_mock1.json"))
        expected_file = os.path.join(TEST_DATA, "expected_curl_advisory_output1.json")
        result = parse_advisory_data(mock_response)
        result = result.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_parse_advisory_data2(self):
        mock_response = load_json(os.path.join(TEST_DATA, "curl_advisory_mock2.json"))
        expected_file = os.path.join(TEST_DATA, "expected_curl_advisory_output2.json")
        result = parse_advisory_data(mock_response)
        result = result.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_parse_advisory_data3(self):
        mock_response = load_json(os.path.join(TEST_DATA, "curl_advisory_mock3.json"))
        expected_file = os.path.join(TEST_DATA, "expected_curl_advisory_output3.json")
        result = parse_advisory_data(mock_response)
        result = result.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_get_cwe_from_curl_advisory(self):
        assert get_cwe_from_curl_advisory(
            {
                "id": "CURL-CVE-2024-2466",
                "database_specific": {
                    "CWE": {
                        "id": "CWE-297",
                        "desc": "Improper Validation of Certificate with Host Mismatch",
                    },
                },
            }
        ) == [297]

        mock_advisory = [
            {
                "id": "CURL-CVE-XXXX-XXXX",
                "database_specific": {"CWE": {"id": "CWE-111111111", "desc": "Invalid weaknesses"}},
            },
            {
                "id": "CURL-CVE-2024-2466",
                "database_specific": {
                    "CWE": {"id": "CWE-311", "desc": "Missing Encryption of Sensitive Data"},
                },
            },
        ]
        mock_cwe_list = []
        for advisory in mock_advisory:
            mock_cwe_list.extend(get_cwe_from_curl_advisory(advisory))
        assert mock_cwe_list == [311]


@pytest.fixture
def mock_curl_api(monkeypatch):
    test_files = [
        "curl_advisory_mock1.json",
        "curl_advisory_mock2.json",
        "curl_advisory_mock3.json",
    ]

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    TEST_DATA = os.path.join(BASE_DIR, "test_data/curl")
    data = []
    for fname in test_files:
        with open(os.path.join(TEST_DATA, fname)) as f:
            data.append(json.load(f))

    def mock_fetch(self):
        return data

    monkeypatch.setattr(CurlImporter, "fetch", mock_fetch)


def test_curl_importer_package_first(monkeypatch, mock_curl_api):
    purl = PackageURL(type="generic", namespace="curl.se", name="curl")
    importer = CurlImporter(purl=purl)
    advisories = list(importer.advisory_data())
    assert len(advisories) == 3
    for adv in advisories:
        assert any(ap.package.name == "curl" for ap in adv.affected_packages)


def test_curl_importer_package_first_version(monkeypatch, mock_curl_api):
    purl = PackageURL(type="generic", namespace="curl.se", name="curl", version="8.6.0")
    importer = CurlImporter(purl=purl)
    advisories = list(importer.advisory_data())

    assert len(advisories) == 1
    assert advisories[0].aliases[0] == "CVE-2024-2379"

    for ap in advisories[0].affected_packages:
        assert ap.affected_version_range.contains(SemverVersion("8.6.0"))


def test_curl_importer_package_first_version_not_affected(monkeypatch, mock_curl_api):
    purl = PackageURL(type="generic", namespace="curl.se", name="curl", version="9.9.9")
    importer = CurlImporter(purl=purl)
    advisories = list(importer.advisory_data())
    assert advisories == []
