#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import shutil
from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.pipelines.v2_importers.elixir_security_importer import (
    ElixirSecurityImporterPipeline,
)


@pytest.fixture
def mock_vcs_response(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    packages_dir = repo_dir / "packages" / "some_package"
    packages_dir.mkdir(parents=True)

    advisory_file = packages_dir / "CVE-2022-9999.yml"
    advisory_file.write_text(
        """
        cve: "2022-9999"
        package: "plug"
        description: "Cross-site scripting vulnerability in plug < 1.11.1"
        patched_versions:
          - ">= 1.11.1"
        unaffected_versions:
          - "< 1.0.0"
        disclosure_date: "2022-12-01"
        link: "https://github.com/plug/plug/security/advisories/GHSA-xxxx-yyyy"
        """
    )

    mock = MagicMock()
    mock.dest_dir = str(repo_dir)
    mock.delete = MagicMock()
    return mock


@pytest.fixture
def mock_fetch_via_vcs(mock_vcs_response):
    with patch(
        "vulnerabilities.pipelines.v2_importers.elixir_security_importer.fetch_via_vcs"
    ) as mock:
        mock.return_value = mock_vcs_response
        yield mock


def test_advisories_count(mock_fetch_via_vcs, mock_vcs_response):
    importer = ElixirSecurityImporterPipeline()
    importer.clone()
    count = importer.advisories_count()
    assert count == 1


def test_collect_advisories(mock_fetch_via_vcs, mock_vcs_response):
    importer = ElixirSecurityImporterPipeline()
    importer.clone()
    advisories = list(importer.collect_advisories())

    assert len(advisories) == 1

    advisory: AdvisoryData = advisories[0]
    assert advisory.advisory_id == "some_package/CVE-2022-9999"
    assert advisory.summary.startswith("Cross-site scripting vulnerability")
    assert advisory.affected_packages[0].package.name == "plug"
    assert advisory.affected_packages[0].package.type == "hex"
    assert (
        advisory.references_v2[0].url
        == "https://github.com/plug/plug/security/advisories/GHSA-xxxx-yyyy"
    )
    assert advisory.date_published.isoformat().startswith("2022-12-01")


def test_collect_advisories_skips_invalid_cve(mock_fetch_via_vcs, tmp_path):
    repo_dir = tmp_path / "repo"
    packages_dir = repo_dir / "packages"

    if packages_dir.exists():
        shutil.rmtree(packages_dir)
    packages_dir.mkdir(parents=True, exist_ok=True)

    advisory_file = packages_dir / "bad_advisory.yml"
    advisory_file.write_text("cve: BAD-ID\npackage: x\n")

    mock_response = MagicMock()
    mock_response.dest_dir = str(repo_dir)
    mock_response.delete = MagicMock()

    with patch(
        "vulnerabilities.pipelines.v2_importers.elixir_security_importer.fetch_via_vcs"
    ) as mock:
        mock.return_value = mock_response
        importer = ElixirSecurityImporterPipeline()
        importer.clone()
        advisories = list(importer.collect_advisories())
        assert len(advisories) == 0


@pytest.fixture
def test_data_dir():
    return Path(__file__).parent.parent / "test_data" / "elixir_security"


@patch("requests.get")
def test_package_first_mode_success(mock_get, test_data_dir):
    directory_response = MagicMock()
    directory_response.status_code = 200
    directory_response.json.return_value = [
        {"name": "test_file.yml", "path": "packages/coherence/test_file.yml"}
    ]

    advisory_file_path = test_data_dir / "test_file.yml"
    advisory_content = advisory_file_path.read_text()

    content_response = MagicMock()
    content_response.status_code = 200
    content_response.text = advisory_content

    mock_get.side_effect = [directory_response, content_response]

    purl = PackageURL(type="hex", name="coherence")
    importer = ElixirSecurityImporterPipeline(purl=purl)
    advisories = list(importer.collect_advisories())

    assert len(advisories) == 1
    advisory = advisories[0]
    assert "CVE-2018-20301" in advisory.aliases
    assert advisory.summary == 'The Coherence library has "Mass Assignment"-like vulnerabilities.'
    assert len(advisory.affected_packages) == 1
    assert advisory.affected_packages[0].package.name == "coherence"


@patch("requests.get")
def test_package_first_mode_with_version_filter(mock_get, test_data_dir):
    directory_response = MagicMock()
    directory_response.status_code = 200
    directory_response.json.return_value = [
        {"name": "test_file.yml", "path": "packages/coherence/test_file.yml"}
    ]

    advisory_file_path = test_data_dir / "test_file.yml"
    advisory_content = advisory_file_path.read_text()

    content_response = MagicMock()
    content_response.status_code = 200
    content_response.text = advisory_content

    mock_get.side_effect = [directory_response, content_response]

    # Version affected
    purl = PackageURL(type="hex", name="coherence", version="0.5.1")
    importer = ElixirSecurityImporterPipeline(purl=purl)
    advisories = list(importer.collect_advisories())
    assert len(advisories) == 1

    # Version not affected
    mock_get.side_effect = [directory_response, content_response]
    purl = PackageURL(type="hex", name="coherence", version="0.5.2")
    importer = ElixirSecurityImporterPipeline(purl=purl)
    advisories = list(importer.collect_advisories())
    assert len(advisories) == 0


@patch("requests.get")
def test_package_first_mode_no_advisories(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_get.return_value = mock_response

    purl = PackageURL(type="hex", name="nonexistent-package")
    importer = ElixirSecurityImporterPipeline(purl=purl)
    advisories = list(importer.collect_advisories())
    assert len(advisories) == 0


@patch("requests.get")
def test_package_first_mode_api_error(mock_get):
    directory_response = MagicMock()
    directory_response.status_code = 200
    directory_response.json.return_value = [
        {"name": "test_file.yml", "path": "packages/coherence/test_file.yml"}
    ]

    content_response = MagicMock()
    content_response.status_code = 500

    mock_get.side_effect = [directory_response, content_response]

    purl = PackageURL(type="hex", name="coherence")
    importer = ElixirSecurityImporterPipeline(purl=purl)
    advisories = list(importer.collect_advisories())
    assert len(advisories) == 0


def test_package_first_mode_non_hex_purl():
    purl = PackageURL(type="npm", name="some-package")
    importer = ElixirSecurityImporterPipeline(purl=purl)
    advisories = list(importer.collect_advisories())
    assert len(advisories) == 0
    advisories = list(importer.collect_advisories())
    assert len(advisories) == 0
