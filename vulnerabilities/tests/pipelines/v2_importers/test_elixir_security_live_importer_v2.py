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
from vulnerabilities.pipelines.v2_importers.elixir_security_live_importer import (
    ElixirSecurityLiveImporterPipeline,
)


@pytest.fixture
def test_data_dir():
    return Path(__file__).parent.parent.parent / "test_data" / "elixir_security"


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
    importer = ElixirSecurityLiveImporterPipeline(purl=purl)
    importer.get_purl_inputs()
    advisories = list(importer.collect_advisories())
    assert len(advisories) == 1

    # Version not affected
    mock_get.side_effect = [directory_response, content_response]
    purl = PackageURL(type="hex", name="coherence", version="0.5.2")
    importer = ElixirSecurityLiveImporterPipeline(purl=purl)
    importer.get_purl_inputs()
    advisories = list(importer.collect_advisories())
    assert len(advisories) == 0


@patch("requests.get")
def test_package_first_mode_no_advisories(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_get.return_value = mock_response

    purl = PackageURL(type="hex", name="nonexistent-package")
    importer = ElixirSecurityLiveImporterPipeline(purl=purl)
    with pytest.raises(ValueError):
        importer.get_purl_inputs()


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

    purl = PackageURL(type="hex", name="coherence", version="0.5.1")
    importer = ElixirSecurityLiveImporterPipeline(purl=purl)
    importer.get_purl_inputs()
    advisories = list(importer.collect_advisories())
    assert len(advisories) == 0


def test_package_first_mode_non_hex_purl():
    purl = PackageURL(type="npm", name="some-package")
    importer = ElixirSecurityLiveImporterPipeline(purl=purl)
    with pytest.raises(ValueError):
        importer.get_purl_inputs()
