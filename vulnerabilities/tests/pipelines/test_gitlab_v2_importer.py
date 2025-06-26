#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
#

from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from vulnerabilities.importer import AdvisoryData


@pytest.fixture
def mock_vcs_response(tmp_path):
    mock_response = MagicMock()
    mock_response.dest_dir = str(tmp_path)
    mock_response.delete = MagicMock()
    return mock_response


@pytest.fixture
def mock_fetch_via_vcs(mock_vcs_response):
    with patch("vulnerabilities.pipelines.v2_importers.gitlab_importer.fetch_via_vcs") as mock:
        mock.return_value = mock_vcs_response
        yield mock


@pytest.fixture
def mock_gitlab_yaml(tmp_path):
    advisory_dir = tmp_path / "pypi" / "package_name"
    advisory_dir.mkdir(parents=True)

    advisory_file = advisory_dir / "CVE-2022-0001.yml"
    advisory_file.write_text(
        """
        identifier: "CVE-2022-0001"
        package_slug: "pypi/package_name"
        title: "Example vulnerability"
        description: "Example description"
        pubdate: "2022-06-15"
        affected_range: "<2.0.0"
        fixed_versions:
          - "2.0.0"
        urls:
          - "https://example.com/advisory"
        cwe_ids:
          - "CWE-79"
        identifiers:
          - "CVE-2022-0001"
        """
    )
    return tmp_path


def test_clone(mock_fetch_via_vcs, mock_vcs_response):
    from vulnerabilities.pipelines.v2_importers.gitlab_importer import GitLabImporterPipeline

    pipeline = GitLabImporterPipeline()
    pipeline.clone()

    mock_fetch_via_vcs.assert_called_once_with(pipeline.repo_url)
    assert pipeline.vcs_response == mock_vcs_response


def test_advisories_count(mock_gitlab_yaml, mock_vcs_response, mock_fetch_via_vcs):
    from vulnerabilities.pipelines.v2_importers.gitlab_importer import GitLabImporterPipeline

    mock_vcs_response.dest_dir = str(mock_gitlab_yaml)

    pipeline = GitLabImporterPipeline()
    pipeline.clone()
    mock_fetch_via_vcs.assert_called_once()

    count = pipeline.advisories_count()
    assert count == 1


def test_collect_advisories(mock_gitlab_yaml, mock_vcs_response, mock_fetch_via_vcs):
    from vulnerabilities.pipelines.v2_importers.gitlab_importer import GitLabImporterPipeline

    mock_vcs_response.dest_dir = str(mock_gitlab_yaml)

    pipeline = GitLabImporterPipeline()
    pipeline.clone()

    advisories = list(pipeline.collect_advisories())
    assert len(advisories) == 1
    advisory = advisories[0]

    assert isinstance(advisory, AdvisoryData)
    assert advisory.advisory_id == "CVE-2022-0001"
    assert advisory.summary == "Example vulnerability\nExample description"
    assert advisory.references_v2[0].url == "https://example.com/advisory"
    assert advisory.affected_packages[0].package.name == "package-name"
    assert advisory.affected_packages[0].fixed_version
    assert advisory.weaknesses[0] == 79


def test_clean_downloads(mock_vcs_response):
    from vulnerabilities.pipelines.v2_importers.gitlab_importer import GitLabImporterPipeline

    pipeline = GitLabImporterPipeline()
    pipeline.vcs_response = mock_vcs_response

    pipeline.clean_downloads()
    mock_vcs_response.delete.assert_called_once()


def test_on_failure(mock_vcs_response):
    from vulnerabilities.pipelines.v2_importers.gitlab_importer import GitLabImporterPipeline

    pipeline = GitLabImporterPipeline()
    pipeline.vcs_response = mock_vcs_response

    with patch.object(pipeline, "clean_downloads") as mock_clean:
        pipeline.on_failure()
        mock_clean.assert_called_once()


def test_collect_advisories_with_invalid_yaml(
    mock_gitlab_yaml, mock_vcs_response, mock_fetch_via_vcs
):
    from vulnerabilities.pipelines.v2_importers.gitlab_importer import GitLabImporterPipeline

    # Add an invalid YAML file
    invalid_file = Path(mock_gitlab_yaml) / "pypi" / "package_name" / "invalid.yml"
    invalid_file.write_text(":::invalid_yaml")

    mock_vcs_response.dest_dir = str(mock_gitlab_yaml)

    pipeline = GitLabImporterPipeline()
    pipeline.clone()

    # Should not raise but skip invalid YAML
    advisories = list(pipeline.collect_advisories())
    assert len(advisories) == 1  # Only one valid advisory is parsed


def test_advisories_count_empty(mock_vcs_response, mock_fetch_via_vcs, tmp_path):
    from vulnerabilities.pipelines.v2_importers.gitlab_importer import GitLabImporterPipeline

    mock_vcs_response.dest_dir = str(tmp_path)

    pipeline = GitLabImporterPipeline()
    pipeline.clone()
    mock_fetch_via_vcs.assert_called_once()

    count = pipeline.advisories_count()
    assert count == 0
