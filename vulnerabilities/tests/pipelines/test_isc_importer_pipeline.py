#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path
from unittest import mock
from unittest.mock import patch

from vulnerabilities.pipelines import isc_importer

TEST_DATA = Path(__file__).parent.parent / "test_data" / "isc" / "isc_expected.json"
HTML_DATA = Path(__file__).parent.parent / "test_data" / "isc" / "isc_test.html"
LINKS_DATA = Path(__file__).parent.parent / "test_data" / "isc" / "isc_links.html"

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}


def test_fetch_advisory_links():
    """Test fetching advisory links from ISC security advisories page."""
    with open(LINKS_DATA) as f:
        mock_html_content = f.read()

    with mock.patch("requests.get") as mock_get:
        mock_get.return_value.content = mock_html_content.encode()
        links = isc_importer.fetch_advisory_links("https://kb.isc.org/docs/aa-00913", headers)

    assert "https://kb.isc.org/v1/docs/cve-2024-12705" in links


def test_fetch_advisory_data():
    """Test fetching and parsing advisory data from an ISC advisory page."""
    with open(HTML_DATA) as f:
        mock_html_content = f.read()

    with mock.patch("requests.get") as mock_get:
        mock_get.return_value.content = mock_html_content.encode()
        advisory_data = isc_importer.fetch_advisory_data(
            "https://kb.isc.org/docs/cve-2024-12705", headers
        )

    assert advisory_data["cve"] == "CVE-2024-12705"
    assert advisory_data["Score"] == "7.5"
    assert advisory_data["severity"] == "High"
    assert "Clients using DNS-over-HTTPS" in advisory_data["Description"]
    assert set(advisory_data["Fixed"]) == {"9.18.33", "9.20.5", "9.21.4"}
    assert len(advisory_data["Affected"]) == 4


@mock.patch("requests.get")
def test_isc_importer_pipeline_collect_advisories(mock_get):
    """Test the `collect_advisories` method in `ISCImporterPipeline`."""
    with open(HTML_DATA) as f:
        mock_html_content = f.read()

    mock_get.return_value.content = mock_html_content.encode()
    pipeline = isc_importer.ISCImporterPipeline()

    with mock.patch(
        "vulnerabilities.pipelines.isc_importer.fetch_advisory_links"
    ) as mock_links, mock.patch(
        "vulnerabilities.pipelines.isc_importer.fetch_advisory_data"
    ) as mock_data:
        mock_links.return_value = ["https://kb.isc.org/docs/cve-2024-12705"]
        mock_data.return_value = {
            "cve": "CVE-2024-12705",
            "cve_link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12705",
            "Score": "7.5",
            "severity": "High",
            "Affected": [["9.18.0", "9.18.32"], ["9.20.0", "9.20.4"], ["9.21.0", "9.21.3"]],
            "Fixed": ["9.18.33", "9.20.5", "9.21.4"],
            "Description": "DNS-over-HTTPS issue.",
            "date_published": "2025-01-29T00:00:00+00:00",
        }
        generator = pipeline.collect_advisories()
        advisories = list(generator)

    assert len(advisories) == 1
    advisory = advisories[0]

    assert advisory.aliases == "CVE-2024-12705"
    assert "DNS-over-HTTPS issue." in advisory.summary
    assert (
        advisory.references[0].url
        == "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12705"
    )
