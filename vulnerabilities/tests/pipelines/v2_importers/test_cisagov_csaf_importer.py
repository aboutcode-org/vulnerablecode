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
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from vulnerabilities.pipelines.v2_importers.cisagov_csaf_importer import (
    CISAGOVCSAFImporterPipeline,
)
from vulnerabilities.pipelines.v2_importers.cisagov_csaf_importer import build_product_id_map
from vulnerabilities.pipelines.v2_importers.cisagov_csaf_importer import parse_csaf_advisory
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "cisagov_csaf"


def test_parse_csaf_advisory_multi_cve():
    """A single CSAF file with multiple CVEs yields one AdvisoryDataV2 per CVE."""
    csaf_file = TEST_DATA / "va-24-201-01.json"
    expected_file = TEST_DATA / "va-24-201-01-expected.json"

    with open(csaf_file) as f:
        raw = json.load(f)

    advisory_url = "https://github.com/cisagov/CSAF/blob/develop/csaf_files/IT/white/2024/va-24-201-01.json"
    results = [adv.to_dict() for adv in parse_csaf_advisory(raw, advisory_url)]

    assert len(results) == 2
    util_tests.check_results_against_json(results, expected_file)


def test_parse_csaf_advisory_ids_and_aliases():
    """The document tracking ID is the advisory_id; the CVE becomes an alias."""
    csaf_file = TEST_DATA / "va-24-201-01.json"
    with open(csaf_file) as f:
        raw = json.load(f)

    advisory_url = "http://test.example.com/advisory"
    advisories = list(parse_csaf_advisory(raw, advisory_url))

    assert advisories[0].advisory_id == "VA-24-201-01"
    assert "CVE-2023-45195" in advisories[0].aliases

    assert advisories[1].advisory_id == "VA-24-201-01"
    assert "CVE-2023-45196" in advisories[1].aliases


def test_parse_csaf_advisory_cvss_severities():
    """CVSS 3.1 scores are parsed into VulnerabilitySeverity with the right system."""
    csaf_file = TEST_DATA / "va-24-201-01.json"
    with open(csaf_file) as f:
        raw = json.load(f)

    advisories = list(parse_csaf_advisory(raw, "http://test.example.com/advisory"))
    assert len(advisories[0].severities) == 1
    sev = advisories[0].severities[0]
    assert sev.system.identifier == "cvssv3.1"
    assert sev.value == "5.3"
    assert sev.scoring_elements == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"


def test_parse_csaf_advisory_cwe_weaknesses():
    """CWE IDs are extracted and stored as integers."""
    csaf_file = TEST_DATA / "va-24-201-01.json"
    with open(csaf_file) as f:
        raw = json.load(f)

    advisories = list(parse_csaf_advisory(raw, "http://test.example.com/advisory"))
    assert advisories[0].weaknesses == [918]
    assert advisories[1].weaknesses == [400]


def test_parse_csaf_advisory_references():
    """Document-level and vulnerability-level references are both collected."""
    csaf_file = TEST_DATA / "va-24-201-01.json"
    with open(csaf_file) as f:
        raw = json.load(f)

    advisories = list(parse_csaf_advisory(raw, "http://test.example.com/advisory"))
    ref_urls = [r.url for r in advisories[0].references]
    assert "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/2024/va-24-201-01.json" in ref_urls
    assert "https://github.com/adminerevo/adminerevo/pull/102/commits/18f3167bbcbec3bc746f62db72e016aa99144efc" in ref_urls


def test_parse_csaf_advisory_no_vulnerabilities():
    """A CSAF document with no vulnerabilities list yields nothing."""
    raw = {
        "document": {
            "tracking": {"id": "TEST-00-001", "initial_release_date": "2024-01-01T00:00:00Z"},
            "notes": [],
            "references": [],
        },
        "product_tree": {},
    }
    results = list(parse_csaf_advisory(raw, "http://test.example.com/advisory"))
    assert results == []


def test_parse_csaf_advisory_skips_vuln_without_cve():
    """Vulnerability entries without a CVE ID are skipped."""
    raw = {
        "document": {
            "tracking": {"id": "TEST-00-002", "initial_release_date": "2024-01-01T00:00:00Z"},
            "notes": [],
            "references": [],
        },
        "product_tree": {},
        "vulnerabilities": [
            {"title": "No CVE here", "notes": []},
        ],
    }
    results = list(parse_csaf_advisory(raw, "http://test.example.com/advisory"))
    assert results == []


def test_build_product_id_map():
    """build_product_id_map returns a flat mapping of product_id to name."""
    product_tree = {
        "branches": [
            {
                "category": "vendor",
                "name": "Acme",
                "branches": [
                    {
                        "category": "product_name",
                        "name": "WidgetPro",
                        "branches": [
                            {
                                "category": "product_version",
                                "name": "1.0",
                                "product": {
                                    "product_id": "CSAFPID-0001",
                                    "name": "WidgetPro 1.0",
                                },
                            }
                        ],
                    }
                ],
            }
        ],
        "relationships": [
            {
                "category": "default_component_of",
                "product_reference": "CSAFPID-0001",
                "relates_to_product_reference": "CSAFPID-0002",
                "full_product_name": {
                    "product_id": "CSAFPID-0003",
                    "name": "WidgetPro 1.0 as component of Suite",
                },
            }
        ],
    }
    result = build_product_id_map(product_tree)
    assert result["CSAFPID-0001"] == "WidgetPro 1.0"
    assert result["CSAFPID-0003"] == "WidgetPro 1.0 as component of Suite"


@pytest.fixture
def mock_vcs_response(tmp_path):
    csaf_dir = tmp_path / "csaf_files" / "IT" / "white" / "2024"
    csaf_dir.mkdir(parents=True)

    src = TEST_DATA / "va-24-201-01.json"
    dest = csaf_dir / "va-24-201-01.json"
    dest.write_text(src.read_text())

    mock = MagicMock()
    mock.dest_dir = str(tmp_path)
    mock.delete = MagicMock()
    return mock


def test_advisories_count(mock_vcs_response):
    pipeline = CISAGOVCSAFImporterPipeline()
    pipeline.vcs_response = mock_vcs_response
    assert pipeline.advisories_count() == 1


def test_collect_advisories_pipeline(mock_vcs_response):
    pipeline = CISAGOVCSAFImporterPipeline()
    pipeline.vcs_response = mock_vcs_response

    advisories = list(pipeline.collect_advisories())
    assert len(advisories) == 2
    ids = {adv.advisory_id for adv in advisories}
    assert ids == {"VA-24-201-01"}


def test_clean_downloads(mock_vcs_response):
    pipeline = CISAGOVCSAFImporterPipeline()
    pipeline.vcs_response = mock_vcs_response
    pipeline.clean_downloads()
    mock_vcs_response.delete.assert_called_once()


def test_pipeline_clone():
    pipeline = CISAGOVCSAFImporterPipeline()
    mock_response = MagicMock()

    with patch(
        "vulnerabilities.pipelines.v2_importers.cisagov_csaf_importer.fetch_via_vcs",
        return_value=mock_response,
    ) as mock_clone:
        pipeline.clone()

    mock_clone.assert_called_once_with(CISAGOVCSAFImporterPipeline.repo_url)
    assert pipeline.vcs_response == mock_response
