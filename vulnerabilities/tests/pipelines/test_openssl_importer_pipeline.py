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
from univers.version_range import OpensslVersionRange
from univers.versions import OpensslVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import openssl_importer
from vulnerabilities.severity_systems import ScoringSystem

EXPECTED_DATA = Path(__file__).parent.parent / "test_data" / "openssl" / "openssl_expected.json"
ADVISORY_HTML_DATA = Path(__file__).parent.parent / "test_data" / "openssl" / "openssl_test.html"


def load_expected_data(file):
    with open(file) as f:
        return json.load(f)


@mock.patch("requests.get")
def test_fetch_advisory_data(mock_get):
    """Test fetching and parsing of advisory data"""

    # expected advisory data
    expected_data = load_expected_data(EXPECTED_DATA)

    with open(ADVISORY_HTML_DATA, "r", encoding="utf-8") as file:
        mock_html_content = file.read()

    mock_response = mock.Mock()
    mock_response.status_code = 200
    mock_response.text = mock_html_content
    mock_response.content = mock_html_content.encode("utf-8")

    mock_get.return_value = mock_response

    advisory_data = openssl_importer.fetch_advisory_data(
        "https://openssl-library.org/news/vulnerabilities/index.html"
    )

    # Validate extracted advisory data
    for i in range(2):
        assert advisory_data[i]["CVE"] == expected_data[i]["aliases"][0]
        assert advisory_data[i]["summary"] == expected_data[i]["summary"]


@mock.patch("requests.get")
def test_openssl_importer_pipeline_collect_advisories(mock_get):
    """test the collect_advisories method in OpenSSLImporterPipeline"""

    with open(ADVISORY_HTML_DATA, "r", encoding="utf-8") as file:
        mock_html_content = file.read()

    # Mock HTTP Response
    mock_response = mock.Mock()
    mock_response.status_code = 200
    mock_response.text = mock_html_content
    mock_response.content = mock_html_content.encode("utf-8")
    mock_get.return_value = mock_response

    pipeline = openssl_importer.OpenSSLImporterPipeline()

    with mock.patch("vulnerabilities.pipelines.openssl_importer.fetch_advisory_data") as mock_data:
        mock_data.return_value = [
            {
                "date_published": "11 February 2025",
                "CVE": "CVE-2024-12797",
                "affected_packages": [
                    "from 3.4.0 before 3.4.1",
                    "from 3.3.0 before 3.3.3",
                    "from 3.2.0 before 3.2.4",
                ],
                "references": [
                    "https://www.cve.org/CVERecord?id=CVE-2024-12797",
                    "https://openssl-library.org/news/secadv/20250211.txt",
                    "https://github.com/openssl/openssl/commit/738d4f9fdeaad57660dcba50a619fafced3fd5e9",
                    "https://github.com/openssl/openssl/commit/87ebd203feffcf92ad5889df92f90bb0ee10a699",
                    "https://github.com/openssl/openssl/commit/798779d43494549b611233f92652f0da5328fbe7",
                ],
                "summary": "Clients using RFC7250 Raw Public Keys (RPKs) to authenticate a server may fail to notice that the server was not authenticated, because handshakes don’t abort as expected when the SSL_VERIFY_PEER verification mode is set.",
                "severity": "High",
            }
        ]
        generator = pipeline.collect_advisories()
        advisories = list(generator)

    assert len(advisories) == 1
    advisory = advisories[0]

    assert advisory.aliases == advisory_data.aliases
    assert advisory.date_published == advisory_data.date_published
    assert advisory.summary == advisory_data.summary
    assert advisory.affected_packages == advisory.affected_packages


advisory_data = AdvisoryData(
    aliases=["CVE-2024-12797"],
    summary="Clients using RFC7250 Raw Public Keys (RPKs) to authenticate a server may fail to notice that the server was not authenticated, because handshakes don’t abort as expected when the SSL_VERIFY_PEER verification mode is set.",
    affected_packages=[
        AffectedPackage(
            package=PackageURL(
                type="openssl",
                namespace=None,
                name="openssl",
                version=None,
                qualifiers={},
                subpath=None,
            ),
            affected_version_range=OpensslVersionRange(
                constraints=(
                    VersionConstraint(comparator="=", version=OpensslVersion(string="3.4.0")),
                    VersionConstraint(comparator="=", version=OpensslVersion(string="3.4.1")),
                )
            ),
            fixed_version=None,
        ),
        AffectedPackage(
            package=PackageURL(
                type="openssl",
                namespace=None,
                name="openssl",
                version=None,
                qualifiers={},
                subpath=None,
            ),
            affected_version_range=OpensslVersionRange(
                constraints=(
                    VersionConstraint(comparator="=", version=OpensslVersion(string="3.3.0")),
                    VersionConstraint(comparator="=", version=OpensslVersion(string="3.3.3")),
                )
            ),
            fixed_version=None,
        ),
        AffectedPackage(
            package=PackageURL(
                type="openssl",
                namespace=None,
                name="openssl",
                version=None,
                qualifiers={},
                subpath=None,
            ),
            affected_version_range=OpensslVersionRange(
                constraints=(
                    VersionConstraint(comparator="=", version=OpensslVersion(string="3.2.0")),
                    VersionConstraint(comparator="=", version=OpensslVersion(string="3.2.4")),
                )
            ),
            fixed_version=None,
        ),
    ],
    references=[
        Reference(
            reference_id="CVE-2024-12797",
            reference_type="",
            url="https://www.cve.org/CVERecord?id=CVE-2024-12797",
            severities=[
                VulnerabilitySeverity(
                    system=ScoringSystem(
                        identifier="generic_textual",
                        name="Generic textual severity rating",
                        url="",
                        notes="Severity for generic scoring systems. Contains generic textual values like High, Low etc",
                    ),
                    value="High",
                    scoring_elements="",
                    published_at=None,
                )
            ],
        ),
        Reference(
            reference_id="CVE-2024-12797",
            reference_type="",
            url="https://openssl-library.org/news/secadv/20250211.txt",
            severities=[
                VulnerabilitySeverity(
                    system=ScoringSystem(
                        identifier="generic_textual",
                        name="Generic textual severity rating",
                        url="",
                        notes="Severity for generic scoring systems. Contains generic textual values like High, Low etc",
                    ),
                    value="High",
                    scoring_elements="",
                    published_at=None,
                )
            ],
        ),
        Reference(
            reference_id="CVE-2024-12797",
            reference_type="",
            url="https://github.com/openssl/openssl/commit/738d4f9fdeaad57660dcba50a619fafced3fd5e9",
            severities=[
                VulnerabilitySeverity(
                    system=ScoringSystem(
                        identifier="generic_textual",
                        name="Generic textual severity rating",
                        url="",
                        notes="Severity for generic scoring systems. Contains generic textual values like High, Low etc",
                    ),
                    value="High",
                    scoring_elements="",
                    published_at=None,
                )
            ],
        ),
        Reference(
            reference_id="CVE-2024-12797",
            reference_type="",
            url="https://github.com/openssl/openssl/commit/87ebd203feffcf92ad5889df92f90bb0ee10a699",
            severities=[
                VulnerabilitySeverity(
                    system=ScoringSystem(
                        identifier="generic_textual",
                        name="Generic textual severity rating",
                        url="",
                        notes="Severity for generic scoring systems. Contains generic textual values like High, Low etc",
                    ),
                    value="High",
                    scoring_elements="",
                    published_at=None,
                )
            ],
        ),
        Reference(
            reference_id="CVE-2024-12797",
            reference_type="",
            url="https://github.com/openssl/openssl/commit/798779d43494549b611233f92652f0da5328fbe7",
            severities=[
                VulnerabilitySeverity(
                    system=ScoringSystem(
                        identifier="generic_textual",
                        name="Generic textual severity rating",
                        url="",
                        notes="Severity for generic scoring systems. Contains generic textual values like High, Low etc",
                    ),
                    value="High",
                    scoring_elements="",
                    published_at=None,
                )
            ],
        ),
    ],
    date_published=datetime.datetime(2025, 2, 11, 0, 0, tzinfo=datetime.timezone.utc),
    weaknesses=[],
    url="https://openssl-library.org/news/vulnerabilities/index.html#CVE-2024-12797",
)
