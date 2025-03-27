#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
from pathlib import Path
from unittest import mock

import pytest
from bs4 import BeautifulSoup
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.pipelines.samba_importer import SambaImporterPipeline
from vulnerabilities.pipelines.samba_importer import parse_announcement_text
from vulnerabilities.tests import util_tests

TEST_DATA = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "test_data", "samba"
)


def test_parse_announcement_text():
    with open(os.path.join(TEST_DATA, "CVE-2023-4154.html.txt")) as f:
        announcement_text = f.read()

    result = parse_announcement_text(announcement_text)

    assert result["cve_id"] is not None
    assert "CVE-2023-4154" in result["cve_id"]
    assert result["subject"] is not None and "password exposure" in result["subject"].lower()
    assert (
        result["affected_versions"] is not None and "samba" in result["affected_versions"].lower()
    )


def test_extract_versions_from_patch_links():
    importer = SambaImporterPipeline()

    patch_links = [
        "https://www.samba.org/samba/ftp/patches/security/samba-4.19.1-security-2023-10-10.patch",
        "https://www.samba.org/samba/ftp/patches/security/samba-4.18.8-security-2023-10-10.patch",
        "https://www.samba.org/samba/ftp/patches/security/samba-4.17.12-security-2023-10-10.patch",
    ]

    extracted_versions = importer.extract_versions_from_patch_links(patch_links)

    assert len(extracted_versions) == 3
    assert all(isinstance(v, str) for v in extracted_versions)
    assert all(v.count(".") >= 2 for v in extracted_versions)


def test_extract_affected_packages_from_detail():
    importer = SambaImporterPipeline()
    importer.log = lambda msg, level=None: None

    fixed_versions = ["4.19.1", "4.18.8", "4.17.12"]
    affected_versions = "All versions since Samba 4.0.0"

    packages = importer.extract_affected_packages_from_detail(affected_versions, fixed_versions)

    assert len(packages) == 3
    assert all(pkg.package.type == "generic" and pkg.package.name == "samba" for pkg in packages)
    assert all(pkg.fixed_version in fixed_versions for pkg in packages)

    packages = importer.extract_affected_packages_from_detail("Samba 4.0.0", [])

    assert len(packages) == 1
    assert packages[0].package.type == "generic"
    assert packages[0].package.name == "samba"


@mock.patch("requests.get")
def test_get_advisory_details(mock_get):
    mock_response = mock.Mock()
    mock_response.raise_for_status.return_value = None

    with open(os.path.join(TEST_DATA, "CVE-2023-4154.html")) as f:
        mock_response.text = f.read()

    mock_get.return_value = mock_response

    importer = SambaImporterPipeline()
    importer.log = lambda msg, level=None: None
    importer.advisory_details_cache = {}

    details = importer.get_advisory_details("CVE-2023-4154")

    assert "cve_id" in details
    assert "CVE-2023-4154" in details["cve_id"]
    assert "subject" in details
    assert "affected_versions" in details
    assert "url" in details

    mock_get.reset_mock()
    importer.get_advisory_details("CVE-2023-4154")
    mock_get.assert_not_called()


@mock.patch("requests.get")
def test_parse_advisory_row(mock_get):
    mock_response = mock.Mock()
    mock_response.raise_for_status.return_value = None

    with open(os.path.join(TEST_DATA, "CVE-2023-4154.html")) as f:
        mock_response.text = f.read()

    mock_get.return_value = mock_response

    row_html = """
    <tr>
        <td>October 10, 2023</td>
        <td>
            <a href="/samba/ftp/patches/security/samba-4.19.1-security-2023-10-10.patch">4.19.1</a>
            <a href="/samba/ftp/patches/security/samba-4.18.8-security-2023-10-10.patch">4.18.8</a>
            <a href="/samba/ftp/patches/security/samba-4.17.12-security-2023-10-10.patch">4.17.12</a>
        </td>
        <td>Password exposure to privileged users and RODCs</td>
        <td>All versions since Samba 4.0.0</td>
        <td><a href="/samba/security/CVE-2023-4154.html">CVE-2023-4154</a></td>
        <td><a href="/samba/security/CVE-2023-4154.html">Announcement</a></td>
    </tr>
    """

    soup = BeautifulSoup(row_html, "html.parser")
    row = soup.find("tr")

    importer = SambaImporterPipeline()
    importer.log = lambda msg, level=None: None
    importer.advisory_details_cache = {}

    advisory = importer.parse_advisory_row(row)

    assert advisory is not None
    assert "CVE-2023-4154" in advisory.aliases
    assert len(advisory.affected_packages) > 0
    assert len(advisory.references) >= 3
    assert any(ref.reference_id == "CVE-2023-4154" for ref in advisory.references)
    assert any("Patch:" in ref.reference_id for ref in advisory.references)


@mock.patch("requests.get")
def test_fetch(mock_get):
    mock_response = mock.Mock()
    mock_response.raise_for_status.return_value = None

    with open(os.path.join(TEST_DATA, "security_advisories.html")) as f:
        mock_response.text = f.read()

    mock_get.return_value = mock_response

    importer = SambaImporterPipeline()
    importer.log = lambda msg, level=None: None

    importer.fetch()

    mock_get.assert_called_once_with("https://www.samba.org/samba/history/security.html")
    assert hasattr(importer, "advisory_data")
    assert hasattr(importer, "advisory_details_cache")


class MockResponse:
    def __init__(self, text, url):
        self.text = text
        self.url = url

    def raise_for_status(self):
        return None


@mock.patch("requests.get")
def test_full_pipeline_execution(mock_get):
    def mock_get_response(url):
        if url == "https://www.samba.org/samba/history/security.html":
            with open(os.path.join(TEST_DATA, "security_advisories.html")) as f:
                return MockResponse(f.read(), url)
        elif "CVE-2023-4154" in url:
            with open(os.path.join(TEST_DATA, "CVE-2023-4154.html")) as f:
                return MockResponse(f.read(), url)
        else:
            with open(os.path.join(TEST_DATA, "CVE-2023-4154.html")) as f:
                return MockResponse(f.read(), url)

    mock_get.side_effect = mock_get_response

    importer = SambaImporterPipeline()
    importer.log = lambda msg, level=None: None

    importer.fetch()

    count = importer.advisories_count()
    assert count > 0

    advisories = list(importer.collect_advisories())
    assert len(advisories) > 0

    assert all(len(advisory.aliases) > 0 for advisory in advisories)
    assert all(advisory.affected_packages for advisory in advisories)
    assert all(advisory.references for advisory in advisories)
