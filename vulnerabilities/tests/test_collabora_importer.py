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
from unittest.mock import MagicMock
from unittest.mock import patch

from vulnerabilities.pipelines.v2_importers.collabora_importer import CollaboraImporterPipeline
from vulnerabilities.pipelines.v2_importers.collabora_importer import parse_advisory

TEST_DATA = os.path.join(os.path.dirname(__file__), "test_data", "collabora")


def load_json(filename):
    with open(os.path.join(TEST_DATA, filename), encoding="utf-8") as f:
        return json.load(f)


class TestCollaboraImporter(TestCase):
    def test_parse_advisory_with_cvss31(self):
        # mock1: GHSA-68v6-r6qq-mmq2, CVSS 3.1 score 5.3, no CWEs
        data = load_json("collabora_mock1.json")
        advisory = parse_advisory(data)
        self.assertIsNotNone(advisory)
        self.assertEqual(advisory.advisory_id, "GHSA-68v6-r6qq-mmq2")
        self.assertIn("CVE-2026-23623", advisory.aliases)
        self.assertEqual(len(advisory.severities), 1)
        self.assertEqual(advisory.severities[0].value, "5.3")
        self.assertIn("CVSS:3.1/", advisory.severities[0].scoring_elements)
        self.assertEqual(advisory.weaknesses, [])
        self.assertEqual(len(advisory.references), 1)
        self.assertIsNotNone(advisory.date_published)

    def test_parse_advisory_with_cvss30_and_cwe(self):
        # mock2: GHSA-7582-pwfh-3pwr, CVSS 3.0 score 9.0, CWE-79
        data = load_json("collabora_mock2.json")
        advisory = parse_advisory(data)
        self.assertIsNotNone(advisory)
        self.assertEqual(advisory.advisory_id, "GHSA-7582-pwfh-3pwr")
        self.assertIn("CVE-2023-34088", advisory.aliases)
        self.assertEqual(len(advisory.severities), 1)
        self.assertEqual(advisory.severities[0].value, "9.0")
        self.assertIn("CVSS:3.0/", advisory.severities[0].scoring_elements)
        self.assertEqual(advisory.weaknesses, [79])

    def test_parse_advisory_missing_ghsa_id_returns_none(self):
        advisory = parse_advisory({"cve_id": "CVE-2024-0001", "summary": "test"})
        self.assertIsNone(advisory)

    def test_parse_advisory_no_cve_id_has_empty_aliases(self):
        data = load_json("collabora_mock1.json")
        data = dict(data)
        data["cve_id"] = None
        advisory = parse_advisory(data)
        self.assertIsNotNone(advisory)
        self.assertEqual(advisory.aliases, [])

    def test_parse_advisory_no_cvss_has_empty_severities(self):
        data = load_json("collabora_mock1.json")
        data = dict(data)
        data["cvss_severities"] = {
            "cvss_v3": {"vector_string": None, "score": None},
            "cvss_v4": None,
        }
        advisory = parse_advisory(data)
        self.assertIsNotNone(advisory)
        self.assertEqual(advisory.severities, [])

    def test_parse_advisory_multiple_cwes(self):
        data = load_json("collabora_mock1.json")
        data = dict(data)
        data["cwe_ids"] = ["CWE-79", "CWE-89", "CWE-200"]
        advisory = parse_advisory(data)
        self.assertIsNotNone(advisory)
        self.assertEqual(advisory.weaknesses, [79, 89, 200])

    def test_parse_advisory_malformed_cwe_skipped(self):
        data = load_json("collabora_mock1.json")
        data = dict(data)
        data["cwe_ids"] = ["CWE-abc", "INVALID", "CWE-79", ""]
        advisory = parse_advisory(data)
        self.assertIsNotNone(advisory)
        self.assertEqual(advisory.weaknesses, [79])

    def test_parse_advisory_no_html_url_empty_references(self):
        data = load_json("collabora_mock1.json")
        data = dict(data)
        data["html_url"] = None
        advisory = parse_advisory(data)
        self.assertIsNotNone(advisory)
        self.assertEqual(advisory.references, [])
        self.assertEqual(advisory.url, "")

    def test_parse_advisory_summary_stored(self):
        data = load_json("collabora_mock1.json")
        advisory = parse_advisory(data)
        self.assertIsNotNone(advisory)
        self.assertIsInstance(advisory.summary, str)
        self.assertEqual(advisory.summary, data["summary"])

    def test_parse_advisory_original_text_is_json(self):
        data = load_json("collabora_mock1.json")
        advisory = parse_advisory(data)
        self.assertIsNotNone(advisory)
        parsed = json.loads(advisory.original_advisory_text)
        self.assertEqual(parsed["ghsa_id"], data["ghsa_id"])


class TestCollaboraImporterPipeline(TestCase):
    def _mock_response(self, data, next_url=None):
        resp = MagicMock()
        resp.json.return_value = data
        resp.raise_for_status.return_value = None
        resp.links = {"next": {"url": next_url}} if next_url else {}
        return resp

    @patch("vulnerabilities.pipelines.v2_importers.collabora_importer.requests.get")
    def test_collect_advisories_single_page(self, mock_get):
        data = load_json("collabora_mock1.json")
        mock_get.return_value = self._mock_response([data])
        advisories = list(CollaboraImporterPipeline().collect_advisories())
        self.assertEqual(len(advisories), 1)
        self.assertEqual(advisories[0].advisory_id, data["ghsa_id"])

    @patch("vulnerabilities.pipelines.v2_importers.collabora_importer.requests.get")
    def test_collect_advisories_pagination(self, mock_get):
        data1 = load_json("collabora_mock1.json")
        data2 = load_json("collabora_mock2.json")
        mock_get.side_effect = [
            self._mock_response([data1], next_url="https://api.github.com/page2"),
            self._mock_response([data2]),
        ]
        advisories = list(CollaboraImporterPipeline().collect_advisories())
        self.assertEqual(len(advisories), 2)
        self.assertEqual(advisories[0].advisory_id, data1["ghsa_id"])
        self.assertEqual(advisories[1].advisory_id, data2["ghsa_id"])

    @patch("vulnerabilities.pipelines.v2_importers.collabora_importer.requests.get")
    def test_collect_advisories_http_error_logs_and_stops(self, mock_get):
        mock_get.side_effect = Exception("connection refused")
        logger_name = "vulnerabilities.pipelines.v2_importers.collabora_importer"
        with self.assertLogs(logger_name, level="ERROR") as cm:
            advisories = list(CollaboraImporterPipeline().collect_advisories())
        self.assertEqual(advisories, [])
        self.assertTrue(any("connection refused" in msg for msg in cm.output))
