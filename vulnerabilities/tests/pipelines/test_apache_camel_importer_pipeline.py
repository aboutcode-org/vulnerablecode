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

from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import MavenVersionRange
from univers.versions import MavenVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import apache_camel_importer
from vulnerabilities.severity_systems import ScoringSystem

EXPECTED_DATA = (
    Path(__file__).parent.parent / "test_data" / "apache_camel" / "apache_camel_expected.json"
)
ADVISORY_HTML_DATA = (
    Path(__file__).parent.parent / "test_data" / "apache_camel" / "apache_camel_test.html"
)


def load_test_data(file):
    with open(file) as f:
        return json.load(f)


@mock.patch("requests.get")
def test_fetch_advisory_data(mock_get):
    """Test fetching and parsing of advisory data"""

    expected_data = load_test_data(EXPECTED_DATA)

    with open(ADVISORY_HTML_DATA, "r", encoding="utf-8") as file:
        mock_html_content = file.read()

    mock_response = mock.Mock()
    mock_response.status_code = 200
    mock_response.text = mock_html_content
    mock_response.content = mock_html_content.encode("utf-8")

    mock_get.return_value = mock_response

    advisory_data = apache_camel_importer.fetch_advisory_data("https://camel.apache.org/security/")

    assert advisory_data[0]["Reference"] == expected_data[0]["aliases"][0]
    assert advisory_data[0]["Description"] == expected_data[0]["summary"]


@mock.patch("vulnerabilities.pipelines.apache_camel_importer.fetch_date_published")
@mock.patch("vulnerabilities.pipelines.apache_camel_importer.fetch_advisory_data")
def test_apache_camel_importer_pipeline_collect_advisories(
    mock_fetch_advisory_data, mock_fetch_date_published
):
    """Test the collect_advisories method in ApacheCamelImporterPipeline"""

    with open(ADVISORY_HTML_DATA, "r", encoding="utf-8") as file:
        mock_html_content = file.read()

    mock_response = mock.Mock()
    mock_response.status_code = 200
    mock_response.text = mock_html_content
    mock_response.content = mock_html_content.encode("utf-8")

    mock_fetch_advisory_data.return_value = [
        {
            "Reference": "CVE-2025-30177",
            "Affected": "Apache Camel 4.10.0 before 4.10.3. Apache Camel 4.8.0 before 4.8.6.",
            "Fixed": "4.8.6 and 4.10.3",
            "Score": "MEDIUM",
            "Description": "Camel-Undertow Message Header Injection via Improper Filtering",
        }
    ]

    mock_fetch_date_published.return_value = "2025-04-01T11:56:30.484000+00:00"

    pipeline = apache_camel_importer.ApacheCamelImporterPipeline()

    generator = pipeline.collect_advisories()
    advisories = list(generator)

    assert len(advisories) == 1
    assert advisories[0].aliases == advisory_data.aliases
    assert advisories[0].date_published == advisory_data.date_published
    assert advisories[0].summary == advisory_data.summary
    assert advisories[0].affected_packages == advisory_data.affected_packages


advisory_data = AdvisoryData(
    aliases=["CVE-2025-30177"],
    summary="Camel-Undertow Message Header Injection via Improper Filtering",
    affected_packages=[
        AffectedPackage(
            package=PackageURL(
                type="maven",
                namespace="org.apache.camel",
                name="camel",
                version=None,
                qualifiers={},
                subpath=None,
            ),
            affected_version_range=MavenVersionRange(
                constraints=(
                    VersionConstraint(comparator="=", version=MavenVersion(string="4.8.0")),
                    VersionConstraint(comparator="=", version=MavenVersion(string="4.8.6")),
                    VersionConstraint(comparator="=", version=MavenVersion(string="4.10.0")),
                    VersionConstraint(comparator="=", version=MavenVersion(string="4.10.3")),
                )
            ),
            fixed_version=None,
        )
    ],
    references=[
        Reference(
            reference_id="CVE-2025-30177",
            reference_type="",
            url="https://camel.apache.org/security/CVE-2025-30177.html",
            severities=[
                VulnerabilitySeverity(
                    system=ScoringSystem(
                        identifier="generic_textual",
                        name="Generic textual severity rating",
                        url="",
                        notes="Severity for generic scoring systems. Contains generic textual values like High, Low etc",
                    ),
                    value="MEDIUM",
                    scoring_elements="",
                    published_at=None,
                )
            ],
        )
    ],
    date_published=datetime.datetime(2025, 4, 1, 11, 56, 30, 484000, tzinfo=datetime.timezone.utc),
    weaknesses=[],
    url="https://camel.apache.org/security/CVE-2025-30177.html",
)
