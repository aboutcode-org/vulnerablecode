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


def test_parse_gitlab_advisory_computes_cvss_scores(tmp_path):
    content = {
        "identifier": "CVE-2019-1010083",
        "package_slug": "pypi/Flask",
        "title": "Denial of service",
        "description": "Denial of Service due to unexpected memory usage in the Pallets Project Flask",
        "pubdate": "2019-07-17",
        "affected_range": "<1.0",
        "fixed_versions": ["1.0"],
        "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2019-1010083"],
        "cvss_v2": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
        "cvss_v3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe_ids": ["CWE-1035", "CWE-937"],
        "identifiers": ["CVE-2019-1010083"],
    }
    advisory_path = tmp_path / "CVE-2019-1010083.yaml"
    advisory_path.write_text(saneyaml.dump(content))

    dummy_logger = lambda *args, **kwargs: None
    result = parse_gitlab_advisory(
        file=advisory_path,
        base_path=advisory_path.parent,
        gitlab_scheme_by_purl_type={"pypi": "pypi"},
        purl_type_by_gitlab_scheme={"pypi": "pypi"},
        logger=dummy_logger,
    )

    assert isinstance(result, AdvisoryDataV2)
    assert len(result.severities) == 2

    cvss_v2_sev = result.severities[0]
    assert cvss_v2_sev.system.identifier == "cvssv2"
    assert cvss_v2_sev.scoring_elements == "AV:N/AC:L/Au:N/C:N/I:N/A:P"
    assert cvss_v2_sev.value == "5.0"

    cvss_v3_sev = result.severities[1]
    assert cvss_v3_sev.system.identifier == "cvssv3"
    assert cvss_v3_sev.scoring_elements == "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    assert cvss_v3_sev.value == "7.5"


def test_parse_gitlab_advisory_cvss_v31_scoring_system(tmp_path):
    content = {
        "identifier": "CVE-2023-0001",
        "package_slug": "pypi/django",
        "title": "Vulnerability with CVSS 3.1",
        "description": "Test CVSS 3.1 scoring system selection and computation",
        "pubdate": "2023-01-01",
        "affected_range": "<4.0.0",
        "fixed_versions": ["4.0.0"],
        "urls": ["https://example.com/advisory"],
        "cvss_v3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_ids": ["CWE-79"],
        "identifiers": ["CVE-2023-0001"],
    }
    advisory_path = tmp_path / "CVE-2023-0001.yaml"
    advisory_path.write_text(saneyaml.dump(content))

    dummy_logger = lambda *args, **kwargs: None
    result = parse_gitlab_advisory(
        file=advisory_path,
        base_path=advisory_path.parent,
        gitlab_scheme_by_purl_type={"pypi": "pypi"},
        purl_type_by_gitlab_scheme={"pypi": "pypi"},
        logger=dummy_logger,
    )

    assert isinstance(result, AdvisoryDataV2)
    assert len(result.severities) == 1
    cvss_v31_sev = result.severities[0]
    assert cvss_v31_sev.system.identifier == "cvssv3.1"
    assert cvss_v31_sev.scoring_elements == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert cvss_v31_sev.value == "9.8"


def test_parse_gitlab_advisory_malformed_cvss_vectors(tmp_path):
    content = {
        "identifier": "CVE-2023-0002",
        "package_slug": "pypi/django",
        "title": "Vulnerability with malformed vectors",
        "description": "Test error handling for malformed CVSS vectors",
        "pubdate": "2023-01-01",
        "affected_range": "<4.0.0",
        "fixed_versions": ["4.0.0"],
        "urls": ["https://example.com/advisory"],
        "cvss_v2": "MALFORMED_CVSS2_VECTOR",
        "cvss_v3": "MALFORMED_CVSS3_VECTOR",
        "cwe_ids": ["CWE-79"],
        "identifiers": ["CVE-2023-0002"],
    }
    advisory_path = tmp_path / "CVE-2023-0002.yaml"
    advisory_path.write_text(saneyaml.dump(content))

    logged_errors = []

    def recording_logger(msg, level=None):
        logged_errors.append((msg, level))

    result = parse_gitlab_advisory(
        file=advisory_path,
        base_path=advisory_path.parent,
        gitlab_scheme_by_purl_type={"pypi": "pypi"},
        purl_type_by_gitlab_scheme={"pypi": "pypi"},
        logger=recording_logger,
    )

    assert isinstance(result, AdvisoryDataV2)
    assert len(result.severities) == 2

    assert result.severities[0].system.identifier == "cvssv2"
    assert result.severities[0].scoring_elements == "MALFORMED_CVSS2_VECTOR"
    assert result.severities[0].value == ""

    assert result.severities[1].system.identifier == "cvssv3"
    assert result.severities[1].scoring_elements == "MALFORMED_CVSS3_VECTOR"
    assert result.severities[1].value == ""

    assert len(logged_errors) == 2
    assert any("Invalid CVSSv2 vector" in msg for msg, _ in logged_errors)
    assert any("Invalid CVSSv3 vector" in msg for msg, _ in logged_errors)
