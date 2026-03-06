#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
from unittest import TestCase

from vulnerabilities.pipelines.v2_importers.grafana_importer import parse_advisory_data
from vulnerabilities.tests import util_tests
from vulnerabilities.utils import load_json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/grafana")


class TestGrafanaImporter(TestCase):
    def test_parse_advisory_with_cvss_and_cwe(self):
        """Advisory with CVE alias, CVSS v3.1 score, CWE, and two version ranges."""
        mock_response = load_json(os.path.join(TEST_DATA, "grafana_advisory_mock1.json"))
        expected_file = os.path.join(TEST_DATA, "expected_grafana_advisory_output1.json")
        result = parse_advisory_data(mock_response, "golang", "github.com/grafana/grafana")
        self.assertIsNotNone(result)
        result = result.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_parse_advisory_no_cvss_no_cwe_no_cve(self):
        """Advisory with no CVE alias, no CVSS score, no CWE weaknesses."""
        mock_response = load_json(os.path.join(TEST_DATA, "grafana_advisory_mock2.json"))
        expected_file = os.path.join(TEST_DATA, "expected_grafana_advisory_output2.json")
        result = parse_advisory_data(mock_response, "golang", "github.com/grafana/loki")
        self.assertIsNotNone(result)
        result = result.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_parse_advisory_missing_ghsa_id_returns_none(self):
        """Advisory without a GHSA ID must be skipped (returns None)."""
        advisory = {
            "ghsa_id": "",
            "cve_id": "CVE-2023-99999",
            "html_url": "https://github.com/grafana/grafana/security/advisories/",
            "summary": "Test",
            "published_at": "2023-01-01T00:00:00Z",
            "vulnerabilities": [],
            "cvss_severities": {"cvss_v3": {"vector_string": None, "score": None}},
            "cwes": [],
        }
        result = parse_advisory_data(advisory, "golang", "github.com/grafana/grafana")
        self.assertIsNone(result)

    def test_parse_advisory_skips_unparseable_version_range(self):
        """Version range that cannot be parsed should produce no affected_packages."""
        advisory = {
            "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
            "cve_id": None,
            "html_url": "https://github.com/grafana/grafana/security/advisories/GHSA-xxxx-xxxx-xxxx",
            "summary": "Test advisory with bad range",
            "published_at": "2023-06-01T10:00:00Z",
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "", "name": "github.com/grafana/grafana"},
                    "vulnerable_version_range": "not_a_valid_range",
                }
            ],
            "cvss_severities": {"cvss_v3": {"vector_string": None, "score": None}},
            "cwes": [],
        }
        result = parse_advisory_data(advisory, "golang", "github.com/grafana/grafana")
        self.assertIsNotNone(result)
        self.assertEqual(result.advisory_id, "GHSA-xxxx-xxxx-xxxx")
        self.assertEqual(result.affected_packages, [])

    def test_parse_advisory_ghsa_id_not_in_aliases(self):
        """GHSA ID must be advisory_id only, not duplicated in aliases."""
        advisory = {
            "ghsa_id": "GHSA-7rqg-hjwc-6mjf",
            "cve_id": "CVE-2023-22462",
            "html_url": "https://github.com/grafana/grafana/security/advisories/GHSA-7rqg-hjwc-6mjf",
            "summary": "Stored XSS in Text plugin",
            "published_at": "2023-03-01T08:59:53Z",
            "vulnerabilities": [],
            "cvss_severities": {"cvss_v3": {"vector_string": None, "score": None}},
            "cwes": [],
        }
        result = parse_advisory_data(advisory, "golang", "github.com/grafana/grafana")
        self.assertIsNotNone(result)
        self.assertEqual(result.advisory_id, "GHSA-7rqg-hjwc-6mjf")
        self.assertNotIn("GHSA-7rqg-hjwc-6mjf", result.aliases)
        self.assertIn("CVE-2023-22462", result.aliases)
