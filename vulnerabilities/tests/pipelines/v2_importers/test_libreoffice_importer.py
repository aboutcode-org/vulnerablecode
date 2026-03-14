#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from unittest import TestCase
from unittest.mock import MagicMock
from unittest.mock import patch

from vulnerabilities.pipelines.v2_importers.libreoffice_importer import LibreOfficeImporterPipeline
from vulnerabilities.pipelines.v2_importers.libreoffice_importer import parse_advisory
from vulnerabilities.pipelines.v2_importers.libreoffice_importer import parse_advisory_urls

LISTING_HTML = """
<p><a href="/about-us/security/advisories/cve-2025-1080/">CVE-2025-1080</a> Macro URL</p>
<p><a href="/about-us/security/advisories/cve-2023-2255/">CVE-2023-2255</a> Macro URL</p>
<p><a href="/about-us/security/advisories/cve-2023-4863/">CVE-2023-4863</a> Heap buffer overflow</p>
"""

ADVISORY_HTML = """\
<html><body id="cve-2025-1080">
<section id="content1"><div class="container"><article>
<div class="row col-sm-10 margin-20">
<ul class="breadcrumb">
<li><a href="/about-us/security/advisories/">Security Advisories</a></li>
<li class="active">CVE-2025-1080</li>
</ul>
<h3>CVE-2025-1080</h3>
<p><strong><span class="label">Title:</span></strong> Macro URL arbitrary script execution</p>
<p><strong>Announced:</strong> March 4, 2025<br/><br/><strong>Fixed in:</strong> LibreOffice 24.8.5 and 25.2.1<br/><br/><strong>Description</strong>:</p>
<p>LibreOffice supports Office URI Schemes to enable browser integration.</p>
<p>In the affected versions a link could call internal macros with arbitrary arguments.</p>
<p><strong>Credits</strong>:</p>
<ul><li>Thanks to Amel Bouziane-Leblond for finding this issue.</li></ul>
<p><strong>References</strong>:<br/><br/><a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-1080" target="_blank">CVE-2025-1080</a></p>
</div>
<div class="col-sm-2"><aside><nav><h3>About Us</h3></nav></aside></div>
</article></div></section>
</body></html>
"""


class TestParseAdvisoryUrls(TestCase):
    def test_extracts_urls_from_html(self):
        urls = parse_advisory_urls(LISTING_HTML)
        self.assertIn(
            "https://www.libreoffice.org/about-us/security/advisories/cve-2025-1080/", urls
        )
        self.assertIn(
            "https://www.libreoffice.org/about-us/security/advisories/cve-2023-2255/", urls
        )
        self.assertIn(
            "https://www.libreoffice.org/about-us/security/advisories/cve-2023-4863/", urls
        )

    def test_deduplicates_repeated_urls(self):
        html = '<a href="/about-us/security/advisories/cve-2025-1080/">x</a>' * 2
        urls = parse_advisory_urls(html)
        self.assertEqual(len(urls), 1)

    def test_empty_html_returns_empty_list(self):
        self.assertEqual(parse_advisory_urls("<html></html>"), [])


class TestParseAdvisory(TestCase):
    URL = "https://www.libreoffice.org/about-us/security/advisories/cve-2025-1080/"

    def test_parses_advisory_id(self):
        advisory = parse_advisory(ADVISORY_HTML, self.URL)
        self.assertIsNotNone(advisory)
        self.assertEqual(advisory.advisory_id, "CVE-2025-1080")

    def test_parses_description_as_summary(self):
        advisory = parse_advisory(ADVISORY_HTML, self.URL)
        self.assertIn("Office URI Schemes", advisory.summary)

    def test_parses_date(self):
        advisory = parse_advisory(ADVISORY_HTML, self.URL)
        self.assertIsNotNone(advisory.date_published)
        self.assertEqual(advisory.date_published.year, 2025)
        self.assertEqual(advisory.date_published.month, 3)
        self.assertEqual(advisory.date_published.day, 4)

    def test_extracts_reference_url(self):
        advisory = parse_advisory(ADVISORY_HTML, self.URL)
        urls = [r.url for r in advisory.references]
        self.assertIn("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-1080", urls)

    def test_severities_and_weaknesses_are_empty(self):
        advisory = parse_advisory(ADVISORY_HTML, self.URL)
        self.assertEqual(advisory.severities, [])
        self.assertEqual(advisory.weaknesses, [])

    def test_missing_body_id_returns_none(self):
        html = (
            "<html><body id='not-a-cve'>"
            "<section id='content1'><div class='margin-20'></div></section>"
            "</body></html>"
        )
        self.assertIsNone(parse_advisory(html, self.URL))

    def test_missing_content_div_returns_none(self):
        html = "<html><body id='cve-2025-1080'><section id='other'></section></body></html>"
        self.assertIsNone(parse_advisory(html, self.URL))

    def test_original_advisory_text_contains_advisory_id(self):
        advisory = parse_advisory(ADVISORY_HTML, self.URL)
        self.assertIn("CVE-2025-1080", advisory.original_advisory_text)


class TestLibreOfficeImporterPipeline(TestCase):
    @patch("vulnerabilities.pipelines.v2_importers.libreoffice_importer.requests.get")
    def test_fetch_stores_advisory_urls(self, mock_get):
        resp = MagicMock()
        resp.text = LISTING_HTML
        resp.raise_for_status.return_value = None
        mock_get.return_value = resp
        pipeline = LibreOfficeImporterPipeline()
        pipeline.fetch()
        self.assertTrue(any("cve-2025-1080" in u for u in pipeline.advisory_urls))
        self.assertTrue(any("cve-2023-2255" in u for u in pipeline.advisory_urls))

    @patch("vulnerabilities.pipelines.v2_importers.libreoffice_importer.requests.get")
    def test_collect_advisories_yields_advisory(self, mock_get):
        resp = MagicMock()
        resp.text = ADVISORY_HTML
        resp.raise_for_status.return_value = None
        mock_get.return_value = resp
        pipeline = LibreOfficeImporterPipeline()
        pipeline.advisory_urls = [
            "https://www.libreoffice.org/about-us/security/advisories/cve-2025-1080/"
        ]
        advisories = list(pipeline.collect_advisories())
        self.assertEqual(len(advisories), 1)
        self.assertEqual(advisories[0].advisory_id, "CVE-2025-1080")

    @patch("vulnerabilities.pipelines.v2_importers.libreoffice_importer.requests.get")
    def test_collect_advisories_skips_on_http_error(self, mock_get):
        mock_get.side_effect = Exception("timeout")
        pipeline = LibreOfficeImporterPipeline()
        pipeline.advisory_urls = [
            "https://www.libreoffice.org/about-us/security/advisories/cve-2025-1080/"
        ]
        logger_name = "vulnerabilities.pipelines.v2_importers.libreoffice_importer"
        with self.assertLogs(logger_name, level="ERROR") as cm:
            advisories = list(pipeline.collect_advisories())
        self.assertEqual(advisories, [])
        self.assertTrue(any("cve-2025-1080" in msg for msg in cm.output))

    def test_advisories_count(self):
        pipeline = LibreOfficeImporterPipeline()
        pipeline.advisory_urls = [
            "https://www.libreoffice.org/about-us/security/advisories/cve-2025-1080/",
            "https://www.libreoffice.org/about-us/security/advisories/cve-2023-2255/",
        ]
        self.assertEqual(pipeline.advisories_count(), 2)
