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
    assert advisory.advisory_id == "CVE-2022-9999"
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
        assert len(advisories) == 0  # Confirm it skipped the invalid CVE
