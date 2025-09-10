#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.importers.cve_schema import parse_cve_v5_advisory
from vulnerabilities.pipelines.v2_importers.cvelistv5_importer import CVEListV5ImporterPipeline


@pytest.fixture
def mock_vcs_response():
    # Mock the vcs_response from fetch_via_vcs
    mock_response = MagicMock()
    mock_response.dest_dir = "/mock/repo"
    mock_response.delete = MagicMock()
    return mock_response


@pytest.fixture
def mock_fetch_via_vcs(mock_vcs_response):
    with patch("vulnerabilities.pipelines.v2_importers.cvelistv5_importer.fetch_via_vcs") as mock:
        mock.return_value = mock_vcs_response
        yield mock


@pytest.fixture
def mock_pathlib(tmp_path):
    # Create a mock filesystem with a 'cves/2021/1xxx' directory and JSON files
    vulns_dir = tmp_path / "cves/2021/1xxx"
    vulns_dir.mkdir(parents=True, exist_ok=True)

    advisory_file = vulns_dir / "CVE-2021-1234.json"
    advisory_file.write_text(
        json.dumps(
            {
                "cveMetadata": {
                    "cveId": "CVE-2021-1234",
                    "state": "PUBLIC",
                    "datePublished": "2021-01-01",
                },
                "containers": {
                    "cna": {
                        "descriptions": [{"lang": "en", "value": "Sample PyPI vulnerability"}],
                        "metrics": [
                            {
                                "cvssV4_0": {
                                    "baseScore": 7.5,
                                    "vectorString": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                }
                            }
                        ],
                        "affected": [{"cpes": ["cpe:/a:example:package"]}],
                        "references": [{"url": "https://example.com", "tags": ["exploit"]}],
                    }
                },
            }
        )
    )
    return vulns_dir


def test_clone(mock_fetch_via_vcs, mock_vcs_response):
    # Test the `clone` method to ensure the repository is cloned correctly
    pipeline = CVEListV5ImporterPipeline()
    pipeline.clone()

    mock_fetch_via_vcs.assert_called_once_with(pipeline.repo_url)
    assert pipeline.vcs_response == mock_vcs_response


def test_advisories_count(mock_pathlib, mock_vcs_response, mock_fetch_via_vcs):
    mock_vcs_response.dest_dir = str(mock_pathlib.parent)

    pipeline = CVEListV5ImporterPipeline()
    pipeline.clone()
    count = pipeline.advisories_count()

    assert count == 0


def test_collect_advisories(mock_pathlib, mock_vcs_response, mock_fetch_via_vcs, tmp_path):
    # Mock `vcs_response.dest_dir` to point to the temporary directory
    mock_vcs_response.dest_dir = str(tmp_path)

    # Mock `parse_cve_advisory` to return an AdvisoryData object
    with patch(
        "vulnerabilities.pipelines.v2_importers.cvelistv5_importer.CVEListV5ImporterPipeline"
    ) as mock_parse:
        mock_parse.return_value = AdvisoryData(
            advisory_id="CVE-2021-1234",
            summary="Sample PyPI vulnerability",
            references_v2=[{"url": "https://example.com"}],
            affected_packages=[],
            weaknesses=[],
            url="https://github.com/CVEProject/cvelistV5/blob/cves/2021/1xxx/CVE-2021-1234.json",
            severities=[
                VulnerabilitySeverity(
                    system="cvssv4",
                    value=7.5,
                    scoring_elements="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                )
            ],
        )

        pipeline = CVEListV5ImporterPipeline()
        pipeline.clone()
        advisories = list(pipeline.collect_advisories())

        # Ensure that advisories are parsed correctly
        assert len(advisories) == 1
        advisory = advisories[0]
        assert advisory.advisory_id == "CVE-2021-1234"
        assert advisory.summary == "Sample PyPI vulnerability"
        assert (
            advisory.url
            == "https://github.com/CVEProject/cvelistV5/blob/main/cves/2021/1xxx/CVE-2021-1234.json"
        )


def test_clean_downloads(mock_vcs_response, mock_fetch_via_vcs):
    # Test the `clean_downloads` method to ensure the repository is deleted
    pipeline = CVEListV5ImporterPipeline()
    pipeline.clone()
    pipeline.vcs_response = mock_vcs_response

    pipeline.clean_downloads()

    mock_vcs_response.delete.assert_called_once()


def test_on_failure(mock_vcs_response, mock_fetch_via_vcs):
    pipeline = CVEListV5ImporterPipeline()
    pipeline.clone()
    pipeline.vcs_response = mock_vcs_response

    with patch.object(pipeline, "clean_downloads") as mock_clean:
        pipeline.on_failure()

        mock_clean.assert_called_once()


def test_parse_cve_advisory(mock_pathlib, mock_vcs_response, mock_fetch_via_vcs):
    mock_vcs_response.dest_dir = str(mock_pathlib.parent)

    raw_data = {
        "cveMetadata": {"cveId": "CVE-2021-1234", "state": "PUBLIC", "datePublished": "2021-01-01"},
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "Sample PyPI vulnerability"}],
                "metrics": [
                    {
                        "cvssV4_0": {
                            "baseScore": 7.5,
                            "vectorString": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                        }
                    }
                ],
                "affected": [{"cpes": ["cpe:/a:example:package"]}],
                "references": [{"url": "https://example.com", "tags": ["exploit"]}],
            }
        },
    }
    advisory_url = "https://github.com/CVEProject/cvelistV5/blob/cves/2021/1xxx/CVE-2021-1234.json"

    pipeline = CVEListV5ImporterPipeline()
    pipeline.clone()
    advisory = parse_cve_v5_advisory(raw_data, advisory_url)

    assert advisory.advisory_id == "CVE-2021-1234"
    assert advisory.summary == "Sample PyPI vulnerability"
    assert advisory.url == advisory_url
    assert len(advisory.severities) == 1
    assert advisory.severities[0].value == 7.5


def test_collect_advisories_with_invalid_json(
    mock_pathlib, mock_vcs_response, mock_fetch_via_vcs, tmp_path
):
    invalid_file = mock_pathlib / "CVE-invalid.json"
    invalid_file.write_text("invalid_json")

    mock_vcs_response.dest_dir = str(tmp_path)

    with patch(
        "vulnerabilities.pipelines.v2_importers.cvelistv5_importer.CVEListV5ImporterPipeline"
    ) as mock_parse:
        mock_parse.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)

        pipeline = CVEListV5ImporterPipeline()
        pipeline.clone()

        with pytest.raises(json.JSONDecodeError):
            list(pipeline.collect_advisories())
