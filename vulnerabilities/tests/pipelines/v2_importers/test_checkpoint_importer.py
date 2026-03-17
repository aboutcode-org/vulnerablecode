#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import datetime
import json
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


class TestParseAdvisory(TestCase):
    def setUp(self):
        self.row = SAMPLE_ROWS[0]

    def test_advisory_id(self):
        advisory = parse_advisory(self.row)
        assert advisory.advisory_id == "CPAI-2026-1780"

    def test_cve_in_aliases(self):
        advisory = parse_advisory(self.row)
        assert "CVE-2026-20122" in advisory.aliases

    def test_date_parsed(self):
        advisory = parse_advisory(self.row)
        assert advisory.date_published is not None
        assert advisory.date_published.year == 2026

    def test_severity_stored(self):
        advisory = parse_advisory(self.row)
        assert len(advisory.severities) == 1
        assert advisory.severities[0].value == "Medium"

    def test_references_include_advisory_url(self):
        advisory = parse_advisory(self.row)
        urls = [r.url for r in advisory.references]
        assert any("cpai-2026-1780.html" in u for u in urls)

    def test_references_include_nvd_url(self):
        advisory = parse_advisory(self.row)
        urls = [r.url for r in advisory.references]
        assert any("nvd.nist.gov" in u for u in urls)

    def test_reference_ids_set(self):
        advisory = parse_advisory(self.row)
        ref_ids = [r.reference_id for r in advisory.references]
        assert "CPAI-2026-1780" in ref_ids
        assert "CVE-2026-20122" in ref_ids

    def test_affected_packages_empty(self):
        advisory = parse_advisory(self.row)
        assert advisory.affected_packages == []

    def test_weaknesses_empty(self):
        advisory = parse_advisory(self.row)
        assert advisory.weaknesses == []

    def test_original_advisory_text_is_pretty_json(self):
        advisory = parse_advisory(self.row)
        parsed = json.loads(advisory.original_advisory_text)
        assert parsed["advisory_id"] == "CPAI-2026-1780"
        assert "\n" in advisory.original_advisory_text

    def test_missing_id_returns_none(self):
        assert parse_advisory({}) is None
        assert parse_advisory({"advisory_id": ""}) is None
        assert parse_advisory({"advisory_id": "INVALID-123"}) is None

    def test_no_cve_yields_empty_aliases(self):
        row = dict(self.row)
        row["cve_id"] = ""
        advisory = parse_advisory(row)
        assert advisory.aliases == []

    def test_critical_severity(self):
        advisory = parse_advisory(SAMPLE_ROWS[1])
        assert advisory.severities[0].value == "Critical"


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
