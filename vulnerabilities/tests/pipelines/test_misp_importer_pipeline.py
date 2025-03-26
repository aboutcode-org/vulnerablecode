#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import datetime
import json
from pathlib import Path
from unittest import mock
from unittest.mock import patch

from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import GenericVersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import misp_importer
from vulnerabilities.severity_systems import Cvssv3ScoringSystem

EXPECTED_DATA = Path(__file__).parent.parent / "test_data" / "misp" / "misp_expected.json"
HTML_DATA = Path(__file__).parent.parent / "test_data" / "misp" / "misp_test.html"
ADVISORY_HTML_DATA = Path(__file__).parent.parent / "test_data" / "misp" / "misp_advisory_test.html"


def load_expected_data(file):
    with open(file) as f:
        return json.load(f)


@mock.patch("requests.get")
def test_fetch_advisory_links(mock_get):
    """Test fetching advisory links from MISP security advisories page."""

    # Read mock HTML content
    with open(HTML_DATA, "r", encoding="utf-8") as file:
        mock_html_content = file.read()

    # Mock HTTP response
    mock_response = mock.Mock()
    mock_response.status_code = 200
    mock_response.content = mock_html_content.encode()

    mock_get.return_value = mock_response

    # Call function under test
    links = misp_importer.fetch_advisory_links("https://www.misp-project.org/security/")

    # Ensure the links are extracted correctly
    assert isinstance(links, list)
    assert len(links) > 0
    assert "https://cve.circl.lu/vuln/fkie_cve-2015-5719" in links


@mock.patch("requests.get")
def test_fetch_advisory_data(mock_get):
    """Test fetching and parsing advisory data from the CVE page."""

    # Load expected advisory data from JSON file
    expected_data = load_expected_data(EXPECTED_DATA)

    # Read mock HTML content
    with open(ADVISORY_HTML_DATA, "r", encoding="utf-8") as file:
        mock_html_content = file.read()

    # Create a proper mock response object
    mock_response = mock.Mock()
    mock_response.status_code = 200
    mock_response.text = mock_html_content
    mock_response.content = mock_html_content.encode("utf-8")

    mock_get.return_value = mock_response

    # Call function under test
    advisory_data = misp_importer.fetch_advisory_data(
        "https://cve.circl.lu/vuln/fkie_cve-2015-5719"
    )

    # Validate extracted advisory data
    assert advisory_data["alias"] == expected_data["aliases"]
    assert advisory_data["description"] == expected_data["summary"]
    assert advisory_data["date_published"] == expected_data["date_published"]


@mock.patch("requests.get")
def test_misp_importer_pipeline_collect_advisories(mock_get):
    """Test the `collect_advisories` method in `MISPImporterPipeline`."""

    with open(ADVISORY_HTML_DATA, "r", encoding="utf-8") as file:
        mock_html_content = file.read()

    # Mock HTTP Response
    mock_response = mock.Mock()
    mock_response.status_code = 200
    mock_response.text = mock_html_content
    mock_response.content = mock_html_content.encode("utf-8")
    mock_get.return_value = mock_response

    # Initialize the pipeline
    pipeline = misp_importer.MISPImporterPipeline()

    with mock.patch(
        "vulnerabilities.pipelines.misp_importer.fetch_advisory_links"
    ) as mock_links, mock.patch(
        "vulnerabilities.pipelines.misp_importer.fetch_advisory_data"
    ) as mock_data:
        mock_links.return_value = ["https://cve.circl.lu/vuln/fkie_cve-2015-5719"]
        mock_data.return_value = {
            "description": "app/Controller/TemplatesController.php in Malware Information Sharing Platform (MISP) before 2.3.92 does not properly restrict filenames under the tmp/files/ directory, which has unspecified impact and attack vectors.",
            "alias": "CVE-2015-5719",
            "date_published": "2016-09-03T20:59:00.153",
            "references": "http://www.securityfocus.com/bid/92740",
            "cve_score": {"version": "cvssMetricV30", "score": 9.8},
            "affected_version": "2.3.92",
        }
        generator = pipeline.collect_advisories()
        advisories = list(generator)

    assert len(advisories) == 1
    advisory = advisories[0]

    assert advisory.aliases == advisory_data.aliases
    assert advisory.date_published == advisory_data.date_published
    assert advisory.summary == advisory_data.summary
    assert advisory.affected_packages == advisory.affected_packages


advisory_data = AdvisoryData(
    aliases="CVE-2015-5719",
    summary="app/Controller/TemplatesController.php in Malware Information Sharing Platform (MISP) before 2.3.92 does not properly restrict filenames under the tmp/files/ directory, which has unspecified impact and attack vectors.",
    affected_packages=[
        AffectedPackage(
            package=PackageURL(
                type="misp", namespace=None, name="MISP", version=None, qualifiers={}, subpath=None
            ),
            affected_version_range=GenericVersionRange(
                constraints=(
                    VersionConstraint(comparator="=", version=SemverVersion(string="2.3.92")),
                )
            ),
            fixed_version=None,
        )
    ],
    references=[
        Reference(
            reference_id="CVE-2015-5719",
            reference_type="",
            url="http://www.securityfocus.com/bid/92740",
            severities=[
                VulnerabilitySeverity(
                    system=Cvssv3ScoringSystem(
                        identifier="cvssv3",
                        name="CVSSv3 Base Score",
                        url="https://www.first.org/cvss/v3-0/",
                        notes="CVSSv3 base score and vector",
                    ),
                    value=9.8,
                    scoring_elements="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    published_at=None,
                )
            ],
        )
    ],
    date_published=datetime.datetime(2016, 9, 3, 20, 59, 0, 153000, tzinfo=datetime.timezone.utc),
    weaknesses=[],
    url="https://cve.circl.lu/vuln/fkie_cve-2015-5719",
)
