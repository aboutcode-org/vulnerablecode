#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from datetime import datetime
from datetime import timezone
from unittest.mock import patch

import pytest
from packageurl import PackageURL
from univers.version_range import GenericVersionRange
from univers.version_range import VersionConstraint
from univers.versions import SemverVersion

from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.pipelines.v2_importers.curl_live_importer import CurlLiveImporterPipeline

SAMPLE_CURL_ADVISORY = {
    "aliases": ["CVE-2024-12345"],
    "id": "CVE-2024-12345",
    "summary": "Sample vulnerability in curl",
    "published": "2024-06-30T08:00:00.00Z",
    "affected": [
        {
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "8.6.0"}, {"fixed": "8.7.0"}]}],
            "versions": ["8.6.0"],
        }
    ],
    "database_specific": {
        "package": "curl",
        "URL": "https://curl.se/docs/CVE-2024-12345.json",
        "www": "https://curl.se/docs/CVE-2024-12345.html",
        "issue": "https://hackerone.com/reports/1111111",
        "severity": "High",
        "CWE": {
            "id": "CWE-119",
            "desc": "Improper restriction of operations within bounds of a memory buffer",
        },
    },
}


@pytest.fixture
def pipeline():
    return CurlLiveImporterPipeline()


@patch("vulnerabilities.pipelines.v2_importers.curl_importer.fetch_response")
def test_live_importer_valid_version(mock_fetch, pipeline):
    mock_fetch.return_value.json.return_value = [SAMPLE_CURL_ADVISORY]
    pipeline.inputs = {"purl": "pkg:generic/curl.se/curl@8.6.0"}

    pipeline.get_purl_inputs()
    advisories = list(pipeline.collect_advisories())

    assert len(advisories) == 1
    advisory = advisories[0]

    assert advisory.advisory_id == "CVE-2024-12345"
    assert advisory.aliases == []
    assert advisory.summary == "Sample vulnerability in curl"
    assert advisory.date_published == datetime(2024, 6, 30, 8, 0, tzinfo=timezone.utc)
    assert advisory.url == "https://curl.se/docs/CVE-2024-12345.json"
    assert advisory.weaknesses == [119]

    # Affected package check
    pkg = advisory.affected_packages[0]
    assert isinstance(pkg, AffectedPackageV2)
    assert pkg.package == PackageURL(type="generic", namespace="curl.se", name="curl")
    assert "8.7.0" in str(pkg.fixed_version_range)
    assert "8.6.0" in str(pkg.affected_version_range)

    # References
    urls = [ref.url for ref in advisory.references_v2]
    assert "https://curl.se/docs/CVE-2024-12345.html" in urls
    assert "https://hackerone.com/reports/1111111" in urls

    # Severity
    severity = advisory.severities[0]
    assert severity.value == "High"


@patch("vulnerabilities.pipelines.v2_importers.curl_importer.fetch_response")
def test_live_importer_invalid_version(mock_fetch, pipeline):
    mock_fetch.return_value.json.return_value = [SAMPLE_CURL_ADVISORY]
    pipeline.inputs = {"purl": "pkg:generic/curl.se/curl@8.5.0"}

    pipeline.get_purl_inputs()
    advisories = list(pipeline.collect_advisories())

    assert len(advisories) == 0


def test_invalid_purl(pipeline):
    pipeline.inputs = {"purl": "pkg:generic/invalid_namespace/curl@invalid_version"}
    with pytest.raises(ValueError):
        pipeline.get_purl_inputs()

    pipeline.inputs = {"purl": "pkg:generic/curl.se/invalid_name@8.6.0"}
    with pytest.raises(ValueError):
        pipeline.get_purl_inputs()
