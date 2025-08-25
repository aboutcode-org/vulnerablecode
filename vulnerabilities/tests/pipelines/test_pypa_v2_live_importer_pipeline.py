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
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData


@pytest.fixture
def mock_github_api_response():
    return {
        "status_code": 200,
        "json": [
            {
                "type": "file",
                "name": "CVE-2022-1234.yaml",
                "download_url": "https://raw.githubusercontent.com/pypa/advisory-database/main/vulns/package1/CVE-2022-1234.yaml",
                "html_url": "https://github.com/pypa/advisory-database/blob/main/vulns/package1/CVE-2022-1234.yaml",
            },
            {
                "type": "file",
                "name": "CVE-2022-5678.yaml",
                "download_url": "https://raw.githubusercontent.com/pypa/advisory-database/main/vulns/package1/CVE-2022-5678.yaml",
                "html_url": "https://github.com/pypa/advisory-database/blob/main/vulns/package1/CVE-2022-5678.yaml",
            },
        ],
    }


@pytest.fixture
def mock_advisory_files():
    advisory1 = {
        "id": "CVE-2022-1234",
        "summary": "A vulnerability in package1",
        "affected": [
            {
                "package": {"name": "package1", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}]}
                ],
            }
        ],
    }

    advisory2 = {
        "id": "CVE-2022-5678",
        "summary": "Another vulnerability in package1",
        "affected": [
            {
                "package": {"name": "package1", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "1.5.0"}, {"fixed": "1.7.0"}]}
                ],
            }
        ],
    }

    return {
        "https://raw.githubusercontent.com/pypa/advisory-database/main/vulns/package1/CVE-2022-1234.yaml": advisory1,
        "https://raw.githubusercontent.com/pypa/advisory-database/main/vulns/package1/CVE-2022-5678.yaml": advisory2,
    }


def test_package_with_version_affected(mock_github_api_response, mock_advisory_files):
    from vulnerabilities.pipelines.v2_importers.pypa_live_importer import PyPaLiveImporterPipeline

    purl = PackageURL(type="pypi", name="package1", version="1.1.0")

    with patch("requests.get") as mock_get:
        mock_api_response = MagicMock()
        mock_api_response.status_code = mock_github_api_response["status_code"]
        mock_api_response.json.return_value = mock_github_api_response["json"]

        def mock_get_side_effect(url, *args, **kwargs):
            if "api.github.com" in url:
                return mock_api_response

            mock_file_response = MagicMock()
            mock_file_response.status_code = 200
            mock_file_response.text = saneyaml.dump(mock_advisory_files[url])
            return mock_file_response

        mock_get.side_effect = mock_get_side_effect

        with patch("vulnerabilities.importers.osv.parse_advisory_data_v2") as mock_parse:

            def side_effect(raw_data, supported_ecosystems, advisory_url, advisory_text):
                return AdvisoryData(
                    advisory_id=raw_data["id"],
                    summary=raw_data["summary"],
                    references_v2=[{"url": advisory_url}],
                    affected_packages=[],
                    weaknesses=[],
                    url=advisory_url,
                )

            mock_parse.side_effect = side_effect

            pipeline = PyPaLiveImporterPipeline(selected_groups=["package_first"], purl=purl)
            pipeline.get_purl_inputs()
            pipeline.fetch_package_advisories()
            advisories = list(pipeline.collect_advisories())

            assert len(advisories) == 1
            assert advisories[0].advisory_id == "CVE-2022-1234"


def test_nonexistent_package():
    from vulnerabilities.pipelines.v2_importers.pypa_live_importer import PyPaLiveImporterPipeline

    purl = PackageURL(type="pypi", name="nonexistent_package", version="1.0.0")

    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        pipeline = PyPaLiveImporterPipeline(selected_groups=["package_first"], purl=purl)
        pipeline.get_purl_inputs()
        pipeline.fetch_package_advisories()
        advisories = list(pipeline.collect_advisories())

        assert len(advisories) == 0
