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
from unittest.mock import Mock
from unittest.mock import patch

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.pipelines.v2_importers.euvd_importer import EUVDImporterPipeline

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "euvd"


class TestEUVDImporterPipeline(TestCase):
    @patch("vulnerabilities.pipelines.v2_importers.euvd_importer.requests.get")
    def test_collect_advisories(self, mock_get):
        """Test collecting and parsing advisories from test data"""
        sample1_path = TEST_DATA / "euvd_sample1.json"
        sample2_path = TEST_DATA / "euvd_sample2.json"

        sample1 = json.loads(sample1_path.read_text(encoding="utf-8"))
        sample2 = json.loads(sample2_path.read_text(encoding="utf-8"))

        mock_responses = [
            Mock(status_code=200, json=lambda: sample1),
            Mock(status_code=200, json=lambda: sample2),
            Mock(status_code=200, json=lambda: {"items": []}),
        ]
        mock_get.side_effect = mock_responses

        pipeline = EUVDImporterPipeline()
        advisories = list(pipeline.collect_advisories())

        assert len(advisories) == 5

        first = advisories[0]
        assert isinstance(first, AdvisoryData)
        assert first.advisory_id == "EUVD-2025-197757"
        assert "EUVD-2025-197757" in first.aliases
        assert "CVE-2025-13284" in first.aliases
        assert first.summary == "ThinPLUS vulnerability that allows remote code execution"
        assert first.date_published is not None
        assert len(first.severities) == 1
        assert first.severities[0].system.identifier == "cvssv3.1"
        assert first.severities[0].value == "9.8"
        assert (
            first.severities[0].scoring_elements == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )

        urls = [ref.url for ref in first.references_v2]
        assert "https://nvd.nist.gov/vuln/detail/CVE-2025-13284" in urls
        assert "https://euvd.enisa.europa.eu/vulnerability/EUVD-2025-197757" in urls

        second = advisories[1]
        assert second.advisory_id == "EUVD-2024-123456"
        assert "CVE-2024-12345" in second.aliases
        assert "CVE-2024-67890" in second.aliases
        assert len([a for a in second.aliases if a.startswith("CVE-")]) == 2

        urls = [ref.url for ref in second.references_v2]
        assert "https://example.com/advisory1" in urls
        assert "https://example.com/advisory2" in urls

        third = advisories[2]
        assert third.advisory_id == "EUVD-2023-999999"
        assert third.severities[0].system.identifier == "cvssv3"
        assert third.severities[0].value == "5.3"

        fourth = advisories[3]
        assert fourth.advisory_id == "EUVD-2022-555555"
        assert fourth.summary == ""
        assert fourth.severities[0].system.identifier == "cvssv2"
        assert fourth.severities[0].value == "4.3"

        fifth = advisories[4]
        assert fifth.advisory_id == "EUVD-2021-111111"
        assert len([a for a in fifth.aliases if a.startswith("CVE-")]) == 0
        assert fifth.summary == "Advisory without CVE alias but with EUVD ID"

    def test_get_scoring_system(self):
        """Test CVSS version to scoring system mapping"""
        pipeline = EUVDImporterPipeline()

        system_v4 = pipeline.get_scoring_system("4.0")
        assert system_v4 is not None
        assert system_v4.identifier == "cvssv4"

        system_v31 = pipeline.get_scoring_system("3.1")
        assert system_v31 is not None
        assert system_v31.identifier == "cvssv3.1"

        system_v3 = pipeline.get_scoring_system("3.0")
        assert system_v3 is not None
        assert system_v3.identifier == "cvssv3"

        system_v2 = pipeline.get_scoring_system("2.0")
        assert system_v2 is not None
        assert system_v2.identifier == "cvssv2"

        system_unknown = pipeline.get_scoring_system("unknown")
        assert system_unknown is None

    @patch("vulnerabilities.pipelines.v2_importers.euvd_importer.requests.get")
    def test_advisories_count(self, mock_get):
        """Test counting advisories"""
        sample_data = {"items": [{"id": "1"}, {"id": "2"}, {"id": "3"}]}
        mock_responses = [
            Mock(status_code=200, json=lambda: sample_data),
            Mock(status_code=200, json=lambda: {"items": []}),
        ]
        mock_get.side_effect = mock_responses

        pipeline = EUVDImporterPipeline()
        count = pipeline.advisories_count()

        assert count == 3
