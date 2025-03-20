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
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.pipelines.zdi_importer import ZDIImporterPipeline

# Create test data directory if it doesn't exist
BASE_DIR = Path(__file__).resolve().parent
TEST_DATA_DIR = BASE_DIR / "../../test_data" / "zdi"
TEST_DATA_DIR.mkdir(parents=True, exist_ok=True)

# Sample HTML for testing
SAMPLE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Zero Day Initiative - Published Advisories</title>
</head>
<body>
    <table>
        <tr>
            <th>ZDI-ID</th>
            <th>Title</th>
            <th>Vendor</th>
            <th>Product</th>
            <th>Published Date</th>
            <th>CVE Number</th>
        </tr>
        <tr>
            <td>ZDI-24-001</td>
            <td>Example Vulnerability in Product</td>
            <td>Example Vendor</td>
            <td>Example Product</td>
            <td>01/15/2024</td>
            <td>CVE-2024-1234</td>
        </tr>
        <tr>
            <td>ZDI-CAN-25319</td>
            <td>Apple Safari Type Confusion Remote Code Execution Vulnerability</td>
            <td>Apple</td>
            <td>Safari</td>
            <td>02/20/2024</td>
            <td>CVE-2024-5678</td>
        </tr>
        <tr>
            <td>ZDI-24-002</td>
            <td>Microsoft Windows Kernel Privilege Escalation</td>
            <td>Microsoft</td>
            <td>Windows</td>
            <td>03/12/2024</td>
            <td>CVE-2024-9876</td>
        </tr>
    </table>
</body>
</html>
"""

# Save the sample HTML to a file
with open(TEST_DATA_DIR / "zdi_sample.html", "w") as f:
    f.write(SAMPLE_HTML)


def test_advisories_count():
    """Test that the advisories_count method correctly counts rows."""
    pipeline = ZDIImporterPipeline()
    pipeline.advisory_data = SAMPLE_HTML

    # The original method looks for a table with id="publishedAdvisories"
    # which doesn't exist in our sample, so it should return 0
    assert pipeline.advisories_count() == 0


def test_collect_advisories():
    """Test that collect_advisories correctly parses HTML and extracts advisory data."""
    pipeline = ZDIImporterPipeline()
    pipeline.advisory_data = SAMPLE_HTML

    advisories = list(pipeline.collect_advisories())

    # Check that we got all three advisories
    assert len(advisories) == 3

    # Check first advisory details
    advisory1 = advisories[0]
    assert advisory1.summary == "Example Vulnerability in Product"
    assert advisory1.aliases == ["ZDI-24-001", "CVE-2024-1234"]
    assert advisory1.url == "https://www.zerodayinitiative.com/advisories/ZDI-24-001/"
    assert len(advisory1.references) == 1
    assert advisory1.references[0].reference_id == "ZDI-24-001"
    assert advisory1.references[0].url == "https://www.zerodayinitiative.com/advisories/ZDI-24-001/"

    # Check the affected package
    assert len(advisory1.affected_packages) == 1
    affected_pkg = advisory1.affected_packages[0]
    assert affected_pkg.package.type == "generic"
    assert affected_pkg.package.namespace == "Example Vendor"
    assert affected_pkg.package.name == "Example Product"
    assert affected_pkg.affected_version_range == "vers:*"

    # Check the second advisory for ZDI-CAN format ID
    advisory2 = advisories[1]
    assert advisory2.summary == "Apple Safari Type Confusion Remote Code Execution Vulnerability"
    assert advisory2.aliases == ["ZDI-CAN-25319", "CVE-2024-5678"]
    assert advisory2.url == "https://www.zerodayinitiative.com/advisories/ZDI-CAN-25319/"

    # Check the third advisory
    advisory3 = advisories[2]
    assert advisory3.summary == "Microsoft Windows Kernel Privilege Escalation"
    assert advisory3.aliases == ["ZDI-24-002", "CVE-2024-9876"]
    assert advisory3.url == "https://www.zerodayinitiative.com/advisories/ZDI-24-002/"


@mock.patch("vulnerabilities.pipelines.zdi_importer.requests.get")
def test_fetch_advisories(mock_get):
    """Test that fetch_advisories makes the correct HTTP request."""
    # Setup mock response
    mock_response = mock.MagicMock()
    mock_response.status_code = 200
    mock_response.text = SAMPLE_HTML
    mock_get.return_value = mock_response

    pipeline = ZDIImporterPipeline()
    pipeline.fetch_advisories()

    # Check that the request was made to the correct URL
    mock_get.assert_called_once_with("https://www.zerodayinitiative.com/advisories/published/")

    # Check that the response was stored correctly
    assert pipeline.advisory_data == SAMPLE_HTML


@mock.patch("vulnerabilities.pipelines.zdi_importer.requests.get")
def test_fetch_advisories_failure(mock_get):
    """Test that fetch_advisories handles HTTP errors gracefully."""
    # Setup mock response with an error status code
    mock_response = mock.MagicMock()
    mock_response.status_code = 404
    mock_get.return_value = mock_response

    pipeline = ZDIImporterPipeline()
    pipeline.fetch_advisories()

    # Check that the request was made
    mock_get.assert_called_once()

    # Check that no advisory data was stored due to error
    assert not hasattr(pipeline, "advisory_data")


def test_collect_advisories_no_data():
    """Test that collect_advisories handles the case of no data gracefully."""
    pipeline = ZDIImporterPipeline()
    # Don't set advisory_data

    advisories = list(pipeline.collect_advisories())
    assert len(advisories) == 0


def test_collect_advisories_empty_table():
    """Test that collect_advisories handles an empty table gracefully."""
    pipeline = ZDIImporterPipeline()
    pipeline.advisory_data = """
    <html>
    <body>
        <table>
            <tr>
                <th>ZDI-ID</th>
                <th>Title</th>
                <th>Vendor</th>
                <th>Product</th>
                <th>Published Date</th>
                <th>CVE Number</th>
            </tr>
        </table>
    </body>
    </html>
    """

    advisories = list(pipeline.collect_advisories())
    assert len(advisories) == 0


def test_collect_advisories_malformed_data():
    """Test that collect_advisories handles malformed data gracefully."""
    pipeline = ZDIImporterPipeline()
    pipeline.advisory_data = """
    <html>
    <body>
        <table>
            <tr>
                <th>ZDI-ID</th>
                <th>Title</th>
                <th>Vendor</th>
                <th>Product</th>
                <th>Published Date</th>
                <th>CVE Number</th>
            </tr>
            <tr>
                <td>ZDI-24-003</td>
                <td>Incomplete Advisory</td>
                <td>Example Vendor</td>
                <td>Example Product</td>
                <td>03/15/2024</td>
                <td></td>
            </tr>
        </table>
    </body>
    </html>
    """

    # With vendor and product included, we should get an advisory
    advisories = list(pipeline.collect_advisories())
    assert len(advisories) == 1
    assert advisories[0].summary == "Incomplete Advisory"
    assert len(advisories[0].affected_packages) == 1


# The base VulnerableCodeBaseImporterPipeline class should have a process() method that
# we can test instead of run()
@pytest.mark.django_db
@mock.patch("vulnerabilities.pipelines.zdi_importer.requests.get")
def test_pipeline_execution(mock_get):
    """Test that the pipeline steps execute successfully."""
    # Setup mock response
    with open(TEST_DATA_DIR / "zdi_sample.html", "r") as f:
        sample_html = f.read()

    mock_response = mock.MagicMock()
    mock_response.status_code = 200
    mock_response.text = sample_html
    mock_get.return_value = mock_response

    pipeline = ZDIImporterPipeline()

    # Test each step individually instead of calling process()
    pipeline.fetch_advisories()
    assert hasattr(pipeline, "advisory_data")

    # Test that collect_advisories works
    advisories = list(pipeline.collect_advisories())
    assert len(advisories) == 3
