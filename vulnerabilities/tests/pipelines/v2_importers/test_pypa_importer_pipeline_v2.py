#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
import saneyaml

from vulnerabilities.importer import AdvisoryDataV2


@pytest.fixture
def mock_vcs_response():
    # Mock the vcs_response from fetch_via_vcs
    mock_response = MagicMock()
    mock_response.dest_dir = "/mock/repo"
    mock_response.delete = MagicMock()
    return mock_response


@pytest.fixture
def mock_fetch_via_vcs(mock_vcs_response):
    with patch("vulnerabilities.pipelines.v2_importers.pypa_importer.fetch_via_vcs") as mock:
        mock.return_value = mock_vcs_response
        yield mock


@pytest.fixture
def mock_pathlib(tmp_path):
    # Mock the Path structure to simulate the `vulns` directory and advisory files
    vulns_dir = tmp_path / "vulns"
    vulns_dir.mkdir()

    advisory_file = vulns_dir / "CVE-2021-1234.yaml"
    advisory_file.write_text(
        """
        id: CVE-2021-1234
        summary: Sample PyPI vulnerability
        references:
          - https://pypi.org/advisory/CVE-2021-1234
        """
    )
    return vulns_dir


def test_clone(mock_fetch_via_vcs, mock_vcs_response):
    # Import inside the test function to avoid circular import
    from vulnerabilities.pipelines.v2_importers.pypa_importer import PyPaImporterPipeline

    # Test the `clone` method to ensure it calls `fetch_via_vcs`
    pipeline = PyPaImporterPipeline()
    pipeline.clone()

    mock_fetch_via_vcs.assert_called_once_with(pipeline.repo_url)
    assert pipeline.vcs_response == mock_vcs_response


def test_advisories_count(mock_pathlib, mock_vcs_response, mock_fetch_via_vcs):
    # Import inside the test function to avoid circular import
    from vulnerabilities.pipelines.v2_importers.pypa_importer import PyPaImporterPipeline

    # Mock `vcs_response.dest_dir` to point to the temporary directory
    mock_vcs_response.dest_dir = str(mock_pathlib.parent)

    pipeline = PyPaImporterPipeline()

    # Call clone() to set the vcs_response attribute
    pipeline.clone()
    mock_fetch_via_vcs.assert_called_once_with(pipeline.repo_url)

    count = pipeline.advisories_count()

    # Check that the count matches the number of YAML files in the `vulns` directory
    assert count == 1


def test_collect_advisories(mock_pathlib, mock_vcs_response, mock_fetch_via_vcs):
    # Import inside the test function to avoid circular import
    from vulnerabilities.pipelines.v2_importers.pypa_importer import PyPaImporterPipeline

    # Mock `vcs_response.dest_dir` to point to the temporary directory
    mock_vcs_response.dest_dir = str(mock_pathlib.parent)

    # Mock `parse_advisory_data` to return an AdvisoryData object
    with patch(
        "vulnerabilities.pipelines.v2_importers.pypa_importer.parse_advisory_data_v3"
    ) as mock_parse:
        mock_parse.return_value = AdvisoryDataV2(
            advisory_id="CVE-2021-1234",
            summary="Sample PyPI vulnerability",
            references=[{"url": "https://pypi.org/advisory/CVE-2021-1234"}],
            affected_packages=[],
            weaknesses=[],
            url="https://pypi.org/advisory/CVE-2021-1234",
        )

        pipeline = PyPaImporterPipeline()
        pipeline.clone()
        mock_fetch_via_vcs.assert_called_once_with(pipeline.repo_url)
        advisories = list(pipeline.collect_advisories())

        # Ensure that advisories are parsed correctly
        assert len(advisories) == 1
        advisory = advisories[0]
        assert advisory.advisory_id == "CVE-2021-1234"
        assert advisory.summary == "Sample PyPI vulnerability"
        assert advisory.url == "https://pypi.org/advisory/CVE-2021-1234"


def test_clean_downloads(mock_vcs_response):
    # Import inside the test function to avoid circular import
    from vulnerabilities.pipelines.v2_importers.pypa_importer import PyPaImporterPipeline

    # Test the `clean_downloads` method to ensure the repository is deleted
    pipeline = PyPaImporterPipeline()
    pipeline.vcs_response = mock_vcs_response

    pipeline.clean_downloads()

    mock_vcs_response.delete.assert_called_once()


def test_on_failure(mock_vcs_response):
    # Import inside the test function to avoid circular import
    from vulnerabilities.pipelines.v2_importers.pypa_importer import PyPaImporterPipeline

    # Test the `on_failure` method to ensure `clean_downloads` is called on failure
    pipeline = PyPaImporterPipeline()
    pipeline.vcs_response = mock_vcs_response

    with patch.object(pipeline, "clean_downloads") as mock_clean:
        pipeline.on_failure()

        mock_clean.assert_called_once()


def test_collect_advisories_with_invalid_yaml(mock_pathlib, mock_vcs_response, mock_fetch_via_vcs):
    # Import inside the test function to avoid circular import
    from vulnerabilities.pipelines.v2_importers.pypa_importer import PyPaImporterPipeline

    # Create an invalid YAML file
    invalid_file = mock_pathlib / "invalid_file.yaml"
    invalid_file.write_text("invalid_yaml")

    mock_vcs_response.dest_dir = str(mock_pathlib.parent)

    with patch(
        "vulnerabilities.pipelines.v2_importers.pypa_importer.parse_advisory_data_v3"
    ) as mock_parse:
        # Mock parse_advisory_data to raise an error on invalid YAML
        mock_parse.side_effect = saneyaml.YAMLError("Invalid YAML")

        pipeline = PyPaImporterPipeline()
        pipeline.clone()
        mock_fetch_via_vcs.assert_called_once_with(pipeline.repo_url)
        with pytest.raises(saneyaml.YAMLError):
            list(pipeline.collect_advisories())


def test_advisories_count_empty(mock_vcs_response, mock_fetch_via_vcs):
    # Import inside the test function to avoid circular import
    from vulnerabilities.pipelines.v2_importers.pypa_importer import PyPaImporterPipeline

    # Mock an empty 'vulns' directory
    mock_vcs_response.dest_dir = "/mock/empty_repo"
    pipeline = PyPaImporterPipeline()
    pipeline.clone()
    # Test that advisories_count returns 0 for an empty directory
    count = pipeline.advisories_count()
    assert count == 0
