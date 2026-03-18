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
from unittest.mock import MagicMock
from unittest.mock import patch

import requests

from vulnerabilities.pipelines.v2_importers.alpine_security_importer import (
    AlpineSecurityImporterPipeline,
)
from vulnerabilities.pipelines.v2_importers.alpine_security_importer import parse_advisory
from vulnerabilities.tests import util_tests
from vulnerabilities.utils import load_json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/alpine_security")


class TestAlpineSecurityImporter(TestCase):
    def test_parse_advisory_with_cvss(self):
        """Advisory with CVSS 3.1 score, references, and no fixed versions."""
        data = load_json(os.path.join(TEST_DATA, "alpine_security_mock1.json"))
        expected = os.path.join(TEST_DATA, "expected_alpine_security_output1.json")
        result = parse_advisory(data)
        self.assertIsNotNone(result)
        util_tests.check_results_against_json(result.to_dict(), expected)

    def test_parse_advisory_with_fixed_states(self):
        """Advisory with no CVSS but multiple fixed package versions across branches."""
        data = load_json(os.path.join(TEST_DATA, "alpine_security_mock2.json"))
        expected = os.path.join(TEST_DATA, "expected_alpine_security_output2.json")
        result = parse_advisory(data)
        self.assertIsNotNone(result)
        util_tests.check_results_against_json(result.to_dict(), expected)

    def test_parse_advisory_missing_id_returns_none(self):
        """Advisory with an empty id field must be skipped."""
        data = {
            "id": "",
            "description": "test",
            "cvss3": {"score": 0.0, "vector": None},
            "ref": [],
            "state": [],
        }
        self.assertIsNone(parse_advisory(data))

    def test_parse_advisory_skips_malformed_package_url(self):
        """State entries with a packageVersion URL too short to parse must be skipped."""
        data = {
            "id": "https://security.alpinelinux.org/vuln/CVE-2099-00001",
            "description": "test",
            "cvss3": {"score": 0.0, "vector": None},
            "ref": [],
            "state": [
                {
                    "fixed": True,
                    "packageVersion": "https://security.alpinelinux.org/srcpkg/",
                    "repo": "edge-main",
                }
            ],
        }
        result = parse_advisory(data)
        self.assertIsNotNone(result)
        self.assertEqual(result.affected_packages, [])

    def test_parse_advisory_skips_unfixed_states(self):
        """State entries with fixed=False must not produce affected_packages."""
        data = {
            "id": "https://security.alpinelinux.org/vuln/CVE-2099-00002",
            "description": "test",
            "cvss3": {"score": 0.0, "vector": None},
            "ref": [],
            "state": [
                {
                    "fixed": False,
                    "packageVersion": "https://security.alpinelinux.org/srcpkg/curl/8.0.0-r0",
                    "repo": "edge-main",
                }
            ],
        }
        result = parse_advisory(data)
        self.assertIsNotNone(result)
        self.assertEqual(result.affected_packages, [])


class TestAlpineSecurityImporterPipeline(TestCase):
    @patch("vulnerabilities.pipelines.v2_importers.alpine_security_importer.get_branches")
    @patch("vulnerabilities.pipelines.v2_importers.alpine_security_importer.requests.get")
    def test_collect_advisories_yields_advisory(self, mock_get, mock_branches):
        mock_branches.return_value = ["3.19-main"]
        data = load_json(os.path.join(TEST_DATA, "alpine_security_mock1.json"))
        resp = MagicMock()
        resp.json.return_value = {"items": [data]}
        resp.raise_for_status.return_value = None
        mock_get.return_value = resp
        advisories = list(AlpineSecurityImporterPipeline().collect_advisories())
        self.assertGreater(len(advisories), 0)

    @patch("vulnerabilities.pipelines.v2_importers.alpine_security_importer.get_branches")
    @patch("vulnerabilities.pipelines.v2_importers.alpine_security_importer.requests.get")
    def test_collect_advisories_http_error_logs_and_continues(self, mock_get, mock_branches):
        mock_branches.return_value = ["3.19-main"]
        mock_get.side_effect = requests.RequestException("timeout")
        logger_name = "vulnerabilities.pipelines.v2_importers.alpine_security_importer"
        with self.assertLogs(logger_name, level="ERROR") as cm:
            advisories = list(AlpineSecurityImporterPipeline().collect_advisories())
        self.assertEqual(advisories, [])
        self.assertTrue(any("timeout" in msg for msg in cm.output))
