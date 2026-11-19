#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import datetime
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock
from unittest.mock import patch

import requests
from bs4 import BeautifulSoup

from vulnerabilities.pipelines.v2_importers.checkpoint_importer import CheckPointImporterPipeline
from vulnerabilities.pipelines.v2_importers.checkpoint_importer import get_available_years
from vulnerabilities.pipelines.v2_importers.checkpoint_importer import get_total_pages
from vulnerabilities.pipelines.v2_importers.checkpoint_importer import parse_advisory
from vulnerabilities.pipelines.v2_importers.checkpoint_importer import parse_table_rows
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "checkpoint"

with open(TEST_DATA / "advisories_2026.html") as f:
    SAMPLE_HTML = f.read()

SAMPLE_ROWS = parse_table_rows(SAMPLE_HTML)


class TestGetAvailableYears(TestCase):
    def test_extracts_years_from_nav_links(self):
        soup = BeautifulSoup(SAMPLE_HTML, features="lxml")
        years = get_available_years(soup)
        current_year = datetime.date.today().year
        assert 2024 in years
        assert 2025 in years
        assert current_year in years

    def test_always_includes_current_year(self):
        soup = BeautifulSoup("<html></html>", features="lxml")
        years = get_available_years(soup)
        assert years == [datetime.date.today().year]


class TestGetTotalPages(TestCase):
    def test_extracts_max_page_from_pagination(self):
        soup = BeautifulSoup(SAMPLE_HTML, features="lxml")
        assert get_total_pages(soup) == 2

    def test_returns_one_when_no_pagination(self):
        soup = BeautifulSoup("<html></html>", features="lxml")
        assert get_total_pages(soup) == 1


class TestParseTableRows(TestCase):
    def test_parses_three_rows(self):
        assert len(SAMPLE_ROWS) == 3

    def test_first_row_advisory_id(self):
        assert SAMPLE_ROWS[0]["advisory_id"] == "CPAI-2026-1780"

    def test_first_row_cve_id(self):
        assert SAMPLE_ROWS[0]["cve_id"] == "CVE-2026-20122"

    def test_first_row_severity(self):
        assert SAMPLE_ROWS[0]["severity"] == "Medium"

    def test_first_row_date(self):
        assert SAMPLE_ROWS[0]["date_published"] == "17 Mar 2026"

    def test_first_row_summary(self):
        assert "Cisco Catalyst" in SAMPLE_ROWS[0]["summary"]

    def test_first_row_advisory_url(self):
        assert SAMPLE_ROWS[0]["advisory_url"].endswith("cpai-2026-1780.html")

    def test_cve_id_stripped_of_extra_text(self):
        assert SAMPLE_ROWS[2]["cve_id"] == "CVE-2025-33603"

    def test_returns_empty_list_for_missing_table(self):
        assert parse_table_rows("<html></html>") == []


def test_parse_advisories():
    results = []
    for row in SAMPLE_ROWS:
        advisory = parse_advisory(row)
        if advisory:
            results.append(advisory.to_dict())
    expected_file = TEST_DATA / "advisories_2026-expected.json"
    util_tests.check_results_against_json(results, expected_file)


def test_missing_id_returns_none():
    assert parse_advisory({}) is None
    assert parse_advisory({"advisory_id": ""}) is None
    assert parse_advisory({"advisory_id": "INVALID-123"}) is None


class TestCheckPointImporterPipeline(TestCase):
    def setUp(self):
        self.pipeline = CheckPointImporterPipeline()
        self.pipeline.advisories_data = SAMPLE_ROWS

    def test_advisories_count(self):
        assert self.pipeline.advisories_count() == 3

    def test_collect_advisories_yields_all_valid(self):
        advisories = list(self.pipeline.collect_advisories())
        assert len(advisories) == 3

    @patch("vulnerabilities.pipelines.v2_importers.checkpoint_importer.requests.get")
    def test_fetch_stores_advisory_rows(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.text = SAMPLE_HTML
        mock_get.return_value = mock_resp
        self.pipeline.fetch()
        assert len(self.pipeline.advisories_data) > 0

    @patch("vulnerabilities.pipelines.v2_importers.checkpoint_importer.requests.get")
    def test_fetch_handles_request_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.RequestException("timeout")
        self.pipeline.fetch()
        assert self.pipeline.advisories_data == []
