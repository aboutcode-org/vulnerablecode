#
# Copyright (c) nexB Inc. and others. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

from datetime import datetime
from datetime import timezone
from unittest.mock import patch

import pytest
from packageurl import PackageURL
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.pipelines.v2_importers.curl_importer import CurlImporterPipeline
from vulnerabilities.pipelines.v2_importers.curl_importer import get_cwe_from_curl_advisory
from vulnerabilities.pipelines.v2_importers.curl_importer import parse_curl_advisory

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
    return CurlImporterPipeline()


@patch("vulnerabilities.pipelines.v2_importers.curl_importer.fetch_response")
def test_advisories_count(mock_fetch, pipeline):
    mock_fetch.return_value.json.return_value = [SAMPLE_CURL_ADVISORY]
    assert pipeline.advisories_count() == 1


@patch("vulnerabilities.pipelines.v2_importers.curl_importer.fetch_response")
def test_collect_advisories(mock_fetch, pipeline):
    mock_fetch.return_value.json.return_value = [SAMPLE_CURL_ADVISORY]
    advisories = list(pipeline.collect_advisories())
    assert len(advisories) == 1

    advisory = advisories[0]
    assert isinstance(advisory, AdvisoryData)
    assert advisory.advisory_id == "CVE-2024-12345"
    assert advisory.aliases == []
    assert advisory.summary == "Sample vulnerability in curl"
    assert advisory.date_published == datetime(2024, 6, 30, 8, 0, tzinfo=timezone.utc)
    assert advisory.url == "https://curl.se/docs/CVE-2024-12345.json"
    assert advisory.weaknesses == [119]

    # Affected package check
    pkg = advisory.affected_packages[0]
    assert isinstance(pkg, AffectedPackage)
    assert pkg.package == PackageURL(type="generic", namespace="curl.se", name="curl")
    assert pkg.fixed_version == SemverVersion("8.7.0")
    assert "8.6.0" in str(pkg.affected_version_range)

    # References
    urls = [ref.url for ref in advisory.references_v2]
    assert "https://curl.se/docs/CVE-2024-12345.html" in urls
    assert "https://hackerone.com/reports/1111111" in urls

    # Severity
    severity = advisory.severities[0]
    assert severity.value == "High"
    assert severity.system.identifier == "cvssv3.1"


def test_parse_curl_advisory_minimal():
    data = dict(SAMPLE_CURL_ADVISORY)
    data.pop("database_specific")
    data["aliases"] = ["CVE-2024-99999"]
    data["id"] = "CVE-2024-99999"
    data["database_specific"] = {}

    parsed = parse_curl_advisory(data)

    assert parsed.advisory_id == "CVE-2024-99999"
    assert parsed.aliases == []
    assert parsed.references_v2 == []
    assert parsed.severities[0].value == ""


def test_get_cwe_from_valid():
    cwe_data = {"database_specific": {"CWE": {"id": "CWE-79", "desc": "Cross-site scripting"}}}
    result = get_cwe_from_curl_advisory(cwe_data)
    assert result == [79]


def test_get_cwe_from_invalid():
    bad_cwe_data = {"database_specific": {"CWE": {"id": "CWE-999999"}}}
    result = get_cwe_from_curl_advisory(bad_cwe_data)
    assert result == []


def test_get_cwe_from_empty():
    empty_cwe_data = {"database_specific": {"CWE": {"id": ""}}}
    result = get_cwe_from_curl_advisory(empty_cwe_data)
    assert result == []
