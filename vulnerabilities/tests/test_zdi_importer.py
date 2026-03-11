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

from vulnerabilities.pipelines.v2_importers.zdi_importer import ZDIImporterPipeline
from vulnerabilities.pipelines.v2_importers.zdi_importer import parse_advisory_data
from vulnerabilities.pipelines.v2_importers.zdi_importer import parse_rss_feed
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/zdi")


def _load_rss(filename="zdi_rss_mock.xml"):
    with open(os.path.join(TEST_DATA, filename), encoding="utf-8") as f:
        return f.read()


class TestZDIImporter(TestCase):
    def test_parse_rss_feed_returns_correct_item_count(self):
        """parse_rss_feed returns one dict per <item> in the RSS feed."""
        items = parse_rss_feed(_load_rss())
        self.assertEqual(len(items), 2)

    def test_parse_rss_feed_item_fields(self):
        """Each parsed item dict contains the expected keys and values."""
        items = parse_rss_feed(_load_rss())
        first = items[0]
        self.assertEqual(
            first["title"], "ZDI-25-001: Example Vendor Product Remote Code Execution Vulnerability"
        )
        self.assertEqual(first["link"], "http://www.zerodayinitiative.com/advisories/ZDI-25-001/")
        self.assertIn("CVE-2025-12345", first["description"])
        self.assertEqual(first["pub_date"], "Mon, 06 Jan 2025 00:00:00 -0600")

    def test_parse_advisory_with_cve(self):
        """Advisory with CVE alias and pubDate is parsed into a correct AdvisoryDataV2."""
        items = parse_rss_feed(_load_rss())
        result = parse_advisory_data(items[0])
        self.assertIsNotNone(result)
        result_dict = result.to_dict()
        expected_file = os.path.join(TEST_DATA, "expected_zdi_advisory_output1.json")
        util_tests.check_results_against_json(result_dict, expected_file)

    def test_parse_advisory_no_cve_has_empty_aliases(self):
        """Advisory whose description contains no CVE IDs has an empty aliases list."""
        items = parse_rss_feed(_load_rss())
        result = parse_advisory_data(items[1])
        self.assertIsNotNone(result)
        self.assertEqual(result.advisory_id, "ZDI-25-002")
        self.assertEqual(result.aliases, [])

    def test_parse_advisory_missing_link_returns_none(self):
        """Advisory with an empty link (no ZDI ID) must return None."""
        item = {
            "title": "ZDI-25-999: Test Advisory",
            "link": "",
            "description": "Some description. CVE-2025-99999.",
            "pub_date": "Mon, 06 Jan 2025 00:00:00 -0600",
        }
        result = parse_advisory_data(item)
        self.assertIsNone(result)

    def test_parse_rss_feed_invalid_xml_returns_empty(self):
        """Malformed XML input returns an empty list without raising."""
        result = parse_rss_feed("not valid xml <>>>")
        self.assertEqual(result, [])

    def test_parse_advisory_zdi_id_not_in_aliases(self):
        """The ZDI advisory ID must be advisory_id only, not duplicated in aliases."""
        item = {
            "title": "ZDI-25-100: Some Vulnerability",
            "link": "http://www.zerodayinitiative.com/advisories/ZDI-25-100/",
            "description": "CVSS 7.0. CVE-2025-11111.",
            "pub_date": "Wed, 08 Jan 2025 00:00:00 -0600",
        }
        result = parse_advisory_data(item)
        self.assertIsNotNone(result)
        self.assertEqual(result.advisory_id, "ZDI-25-100")
        self.assertNotIn("ZDI-25-100", result.aliases)
        self.assertIn("CVE-2025-11111", result.aliases)


class TestZDIImporterPipeline(TestCase):
    @patch("vulnerabilities.pipelines.v2_importers.zdi_importer.fetch_response")
    def test_collect_advisories_yields_advisory(self, mock_fetch):
        resp = MagicMock()
        resp.text = _load_rss()
        mock_fetch.return_value = resp
        advisories = list(ZDIImporterPipeline().collect_advisories())
        self.assertGreater(len(advisories), 0)
        self.assertEqual(advisories[0].advisory_id, "ZDI-25-001")

    @patch("vulnerabilities.pipelines.v2_importers.zdi_importer.fetch_response")
    def test_collect_advisories_http_error_logs_and_continues(self, mock_fetch):
        mock_fetch.side_effect = Exception("connection refused")
        logger_name = "vulnerabilities.pipelines.v2_importers.zdi_importer"
        with self.assertLogs(logger_name, level="ERROR") as cm:
            advisories = list(ZDIImporterPipeline().collect_advisories())
        self.assertEqual(advisories, [])
        self.assertTrue(any("connection refused" in msg for msg in cm.output))
