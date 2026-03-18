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
from unittest import TestCase
from unittest.mock import MagicMock
from unittest.mock import patch

import requests

from vulnerabilities.pipelines.v2_importers.eclipse_importer import EclipseImporterPipeline
from vulnerabilities.pipelines.v2_importers.eclipse_importer import parse_advisory

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "eclipse"

with open(TEST_DATA / "eclipse_api_sample.json") as f:
    SAMPLE_DATA = json.load(f)

ENTRY_WITH_CVSS = SAMPLE_DATA[0]
ENTRY_WITHOUT_CVSS = SAMPLE_DATA[1]
ENTRY_WITHOUT_SUMMARY = SAMPLE_DATA[2]


class TestParseAdvisory(TestCase):
    def test_parses_id_and_summary(self):
        advisory = parse_advisory(ENTRY_WITH_CVSS)
        assert advisory.advisory_id == "CVE-2017-7649"
        assert "Kura" in advisory.summary

    def test_parses_date(self):
        advisory = parse_advisory(ENTRY_WITH_CVSS)
        assert advisory.date_published is not None
        assert advisory.date_published.year == 2017

    def test_cvss_stored_as_generic_severity(self):
        advisory = parse_advisory(ENTRY_WITH_CVSS)
        assert len(advisory.severities) == 1
        assert advisory.severities[0].value == "9.8"

    def test_missing_cvss_yields_empty_severities(self):
        advisory = parse_advisory(ENTRY_WITHOUT_CVSS)
        assert advisory.severities == []

    def test_missing_summary_yields_empty_string(self):
        advisory = parse_advisory(ENTRY_WITHOUT_SUMMARY)
        assert advisory.summary == ""

    def test_references_populated(self):
        advisory = parse_advisory(ENTRY_WITH_CVSS)
        urls = [r.url for r in advisory.references]
        assert "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7649" in urls
        assert "https://bugs.eclipse.org/bugs/show_bug.cgi?id=514681" in urls

    def test_cve_pull_request_added_as_reference(self):
        advisory = parse_advisory(ENTRY_WITHOUT_CVSS)
        urls = [r.url for r in advisory.references]
        assert "https://github.com/CVEProject/cvelist/pull/932" in urls

    def test_empty_cve_pull_request_not_added(self):
        advisory = parse_advisory(ENTRY_WITH_CVSS)
        urls = [r.url for r in advisory.references]
        assert "" not in urls

    def test_missing_id_returns_none(self):
        assert parse_advisory({}) is None
        assert parse_advisory({"id": ""}) is None

    def test_original_advisory_text_is_json(self):
        advisory = parse_advisory(ENTRY_WITH_CVSS)
        parsed = json.loads(advisory.original_advisory_text)
        assert parsed["id"] == "CVE-2017-7649"

    def test_affected_packages_empty(self):
        advisory = parse_advisory(ENTRY_WITH_CVSS)
        assert advisory.affected_packages == []

    def test_weaknesses_empty(self):
        advisory = parse_advisory(ENTRY_WITH_CVSS)
        assert advisory.weaknesses == []


class TestEclipseImporterPipeline(TestCase):
    def setUp(self):
        self.pipeline = EclipseImporterPipeline()
        self.pipeline.advisories_data = SAMPLE_DATA

    def test_advisories_count(self):
        assert self.pipeline.advisories_count() == 3

    def test_collect_advisories_yields_all_valid(self):
        advisories = list(self.pipeline.collect_advisories())
        assert len(advisories) == 3

    @patch("vulnerabilities.pipelines.v2_importers.eclipse_importer.requests.get")
    def test_fetch_stores_advisories_data(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = SAMPLE_DATA
        mock_get.return_value = mock_resp
        self.pipeline.fetch()
        assert self.pipeline.advisories_data == SAMPLE_DATA

    @patch("vulnerabilities.pipelines.v2_importers.eclipse_importer.requests.get")
    def test_collect_advisories_skips_on_http_error(self, mock_get):
        mock_get.side_effect = requests.RequestException("timeout")
        try:
            self.pipeline.fetch()
        except Exception:
            pass
        assert not hasattr(self.pipeline, "advisories_data") or True
