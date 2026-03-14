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

from vulnerabilities.pipelines.v2_importers.libreoffice_importer import LibreOfficeImporterPipeline
from vulnerabilities.pipelines.v2_importers.libreoffice_importer import parse_cve_advisory
from vulnerabilities.pipelines.v2_importers.libreoffice_importer import parse_cve_ids

TEST_DATA = os.path.join(os.path.dirname(__file__), "..", "..", "test_data", "libreoffice")


def load_json(filename):
    with open(os.path.join(TEST_DATA, filename), encoding="utf-8") as f:
        return json.load(f)


def load_html(filename):
    with open(os.path.join(TEST_DATA, filename), encoding="utf-8") as f:
        return f.read()


class TestParseCveIds(TestCase):
    def test_extracts_cve_ids_from_html(self):
        html = load_html("advisories.html")
        cve_ids = parse_cve_ids(html)
        self.assertIn("CVE-2025-1080", cve_ids)
        self.assertIn("CVE-2023-2255", cve_ids)
        self.assertIn("CVE-2023-4863", cve_ids)

    def test_deduplicates_repeated_ids(self):
        html = "<a>CVE-2025-1080</a> ... <a>CVE-2025-1080</a>"
        self.assertEqual(parse_cve_ids(html), ["CVE-2025-1080"])

    def test_empty_html_returns_empty_list(self):
        self.assertEqual(parse_cve_ids("<html></html>"), [])


class TestParseCveAdvisory(TestCase):
    def test_cvss4_and_cwe(self):
        data = load_json("cve_2025_1080.json")
        advisory = parse_cve_advisory(data, "CVE-2025-1080")
        self.assertIsNotNone(advisory)
        self.assertEqual(advisory.advisory_id, "CVE-2025-1080")
        self.assertEqual(advisory.aliases, [])
        self.assertIn("macro", advisory.summary.lower())
        self.assertEqual(len(advisory.severities), 1)
        self.assertEqual(advisory.severities[0].value, "7.2")
        self.assertIn("CVSS:4.0/", advisory.severities[0].scoring_elements)
        self.assertEqual(advisory.weaknesses, [20])
        self.assertIsNotNone(advisory.date_published)
        self.assertIn("cve-2025-1080", advisory.url)

    def test_no_cvss_has_empty_severities(self):
        data = load_json("cve_2023_2255.json")
        advisory = parse_cve_advisory(data, "CVE-2023-2255")
        self.assertIsNotNone(advisory)
        self.assertEqual(advisory.severities, [])

    def test_cwe_264_extracted(self):
        data = load_json("cve_2023_2255.json")
        advisory = parse_cve_advisory(data, "CVE-2023-2255")
        self.assertEqual(advisory.weaknesses, [264])

    def test_references_from_cna(self):
        data = load_json("cve_2023_2255.json")
        advisory = parse_cve_advisory(data, "CVE-2023-2255")
        urls = [r.url for r in advisory.references]
        self.assertIn("https://www.debian.org/security/2023/dsa-5415", urls)
        self.assertIn("https://security.gentoo.org/glsa/202311-15", urls)

    def test_missing_cve_id_returns_none(self):
        advisory = parse_cve_advisory({"cveMetadata": {"cveId": ""}, "containers": {}}, "")
        self.assertIsNone(advisory)

    def test_original_advisory_text_is_json(self):
        data = load_json("cve_2025_1080.json")
        advisory = parse_cve_advisory(data, "CVE-2025-1080")
        parsed = json.loads(advisory.original_advisory_text)
        self.assertEqual(parsed["cveMetadata"]["cveId"], "CVE-2025-1080")

    def test_malformed_cwe_skipped(self):
        data = load_json("cve_2025_1080.json")
        data = json.loads(json.dumps(data))
        data["containers"]["cna"]["problemTypes"] = [
            {"descriptions": [{"cweId": "CWE-INVALID", "lang": "en", "type": "CWE"}]}
        ]
        advisory = parse_cve_advisory(data, "CVE-2025-1080")
        self.assertEqual(advisory.weaknesses, [])


class TestLibreOfficeImporterPipeline(TestCase):
    def _make_resp(self, data, status=200):
        resp = MagicMock()
        resp.json.return_value = data
        resp.text = json.dumps(data)
        resp.raise_for_status.return_value = None
        resp.status_code = status
        return resp

    @patch("vulnerabilities.pipelines.v2_importers.libreoffice_importer.requests.get")
    def test_fetch_stores_cve_ids(self, mock_get):
        html = load_html("advisories.html")
        mock_get.return_value = MagicMock(text=html, raise_for_status=MagicMock())
        pipeline = LibreOfficeImporterPipeline()
        pipeline.fetch()
        self.assertIn("CVE-2025-1080", pipeline.cve_ids)
        self.assertIn("CVE-2023-2255", pipeline.cve_ids)

    @patch("vulnerabilities.pipelines.v2_importers.libreoffice_importer.requests.get")
    def test_collect_advisories_yields_advisory(self, mock_get):
        cve_data = load_json("cve_2025_1080.json")
        pipeline = LibreOfficeImporterPipeline()
        pipeline.cve_ids = ["CVE-2025-1080"]
        mock_get.return_value = self._make_resp(cve_data)
        advisories = list(pipeline.collect_advisories())
        self.assertEqual(len(advisories), 1)
        self.assertEqual(advisories[0].advisory_id, "CVE-2025-1080")

    @patch("vulnerabilities.pipelines.v2_importers.libreoffice_importer.requests.get")
    def test_collect_advisories_skips_on_http_error(self, mock_get):
        pipeline = LibreOfficeImporterPipeline()
        pipeline.cve_ids = ["CVE-2025-1080"]
        mock_get.side_effect = Exception("timeout")
        logger_name = "vulnerabilities.pipelines.v2_importers.libreoffice_importer"
        with self.assertLogs(logger_name, level="ERROR") as cm:
            advisories = list(pipeline.collect_advisories())
        self.assertEqual(advisories, [])
        self.assertTrue(any("CVE-2025-1080" in msg for msg in cm.output))

    def test_advisories_count(self):
        pipeline = LibreOfficeImporterPipeline()
        pipeline.cve_ids = ["CVE-2025-1080", "CVE-2023-2255"]
        self.assertEqual(pipeline.advisories_count(), 2)
