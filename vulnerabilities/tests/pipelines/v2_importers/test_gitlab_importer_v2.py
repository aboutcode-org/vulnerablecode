#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
#

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
import saneyaml

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.pipelines.v2_importers.gitlab_importer import parse_gitlab_advisory


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

    assert isinstance(advisory, AdvisoryDataV2)
    assert advisory.advisory_id == "pypi/package_name/CVE-2022-0001"
    assert advisory.summary == "Example vulnerability\nExample description"
    assert advisory.references[0].url == "https://example.com/advisory"
    assert advisory.affected_packages[0].package.name == "package-name"
    assert str(advisory.affected_packages[0].fixed_version_range) == "vers:pypi/2.0.0"
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


@pytest.fixture
def gitlab_advisory_yaml(tmp_path):
    content = {
        "identifier": "GMS-2018-26",
        "package_slug": "pypi/django",
        "title": "Incorrect header injection check",
        "description": "django isn't properly protected against HTTP header injection.",
        "pubdate": "2018-03-15",
        "affected_range": "<2.0.1",
        "fixed_versions": ["v2.0.1"],
        "urls": ["https://github.com/django/django/pull/123"],
        "cwe_ids": ["CWE-1035", "CWE-937"],
        "identifiers": ["GMS-2018-26"],
    }

    advisory_path = tmp_path / "GMS-2018-26.yaml"
    advisory_path.write_text(saneyaml.dump(content))
    return advisory_path, content


def test_parse_gitlab_advisory_with_no_purl(monkeypatch, gitlab_advisory_yaml):
    file_path, advisory_data = gitlab_advisory_yaml

    # Mock get_purl to always return None
    def mock_get_purl(package_slug, purl_type_by_gitlab_scheme, logger):
        return None

    # Patch the dependencies
    import vulnerabilities.pipelines.v2_importers.gitlab_importer as gitlab_module

    monkeypatch.setattr(gitlab_module, "get_purl", mock_get_purl)

    dummy_logger = lambda *args, **kwargs: None  # Ignore logging in test

    result = parse_gitlab_advisory(
        file=file_path,
        base_path=file_path.parent,
        gitlab_scheme_by_purl_type={},
        purl_type_by_gitlab_scheme={},
        logger=dummy_logger,
    )

    assert isinstance(result, AdvisoryDataV2)
    assert result.advisory_id == "pypi/django/GMS-2018-26"
    assert result.aliases == ["GMS-2018-26"]
    assert result.summary.startswith("Incorrect header")
    assert result.url.startswith("https://gitlab.com/gitlab-org/advisories-community")
    assert isinstance(result.date_published, datetime)
    assert result.date_published.year == 2018
    assert result.affected_packages == []  # Because get_purl was mocked to return None


def test_parse_gitlab_advisory_v_prefix_fixed_version(tmp_path):
    """
    Regression test for https://github.com/aboutcode-org/vulnerablecode/issues/2411

    GitLab advisories sometimes carry fixed_versions with a leading "v" prefix
    (e.g. "v2.28.2") that certain version classes reject, causing the version
    to be silently discarded.  The importer must strip the prefix and still
    produce a valid AdvisoryDataV2 with a non-empty fixed_version_range.

    The advisory intentionally has no affected_range so that the only path to
    a stored fixed_version_range is through the normalized fixed_version.
    """
    content = {
        "identifier": "CVE-2023-9999",
        "package_slug": "pypi/requests",
        "title": "Example v-prefix vulnerability",
        "description": "A test advisory with a v-prefixed fixed version.",
        "pubdate": "2023-01-10",
        # No affected_range -- the only version data is the v-prefixed fixed version.
        # Without the fix this advisory would be stored with no affected_packages.
        "fixed_versions": ["v2.28.2"],
        "urls": ["https://example.com/advisory"],
        "cwe_ids": [],
        "identifiers": ["CVE-2023-9999"],
    }
    advisory_path = tmp_path / "CVE-2023-9999.yml"
    advisory_path.write_text(saneyaml.dump(content))

    dummy_logger = lambda *args, **kwargs: None

    result = parse_gitlab_advisory(
        file=advisory_path,
        base_path=tmp_path,
        gitlab_scheme_by_purl_type={"pypi": "pypi"},
        purl_type_by_gitlab_scheme={"pypi": "pypi"},
        logger=dummy_logger,
    )

    assert isinstance(result, AdvisoryDataV2)
    assert result.affected_packages, "Expected at least one affected_package"
    fixed_range = result.affected_packages[0].fixed_version_range
    assert fixed_range is not None, "fixed_version_range must not be None"
    # "2.28.2" must appear in the range string despite the input being "v2.28.2"
    assert "2.28.2" in str(fixed_range), f"Unexpected fixed_version_range: {fixed_range}"


def test_parse_gitlab_advisory_unparsable_version_still_stored(tmp_path):
    """
    Regression test for https://github.com/aboutcode-org/vulnerablecode/issues/2412

    When neither the affected_range nor any fixed_version can be parsed, the
    advisory must still be returned (without affected_packages) rather than
    silently dropped.  This allows downstream improvers to enrich the record
    with version data later.
    """
    content = {
        "identifier": "CVE-2023-8888",
        "package_slug": "pypi/somelib",
        "title": "Advisory with unparsable version",
        "description": "Version string is deliberately invalid.",
        "pubdate": "2023-05-01",
        # No affected_range and an unparsable fixed_version.
        # Before the fix, parse_gitlab_advisory returned None here.
        "fixed_versions": ["!!!invalid!!!"],
        "urls": ["https://example.com/advisory2"],
        "cwe_ids": [],
        "identifiers": ["CVE-2023-8888"],
    }
    advisory_path = tmp_path / "CVE-2023-8888.yml"
    advisory_path.write_text(saneyaml.dump(content))

    dummy_logger = lambda *args, **kwargs: None

    result = parse_gitlab_advisory(
        file=advisory_path,
        base_path=tmp_path,
        gitlab_scheme_by_purl_type={"pypi": "pypi"},
        purl_type_by_gitlab_scheme={"pypi": "pypi"},
        logger=dummy_logger,
    )

    # Must NOT be None -- advisory should be stored even when version parsing fails
    assert (
        result is not None
    ), "Advisory must not be silently dropped when version parsing fails (issue #2412)"
    assert isinstance(result, AdvisoryDataV2)
    assert result.advisory_id == "pypi/somelib/CVE-2023-8888"
    assert result.summary == (
        "Advisory with unparsable version\nVersion string is deliberately invalid."
    )
    # No affected_packages because no version string could be parsed
    assert result.affected_packages == []
