#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest
import requests

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.pipelines.v2_importers.apache_httpd_importer import ApacheHTTPDImporterPipeline
from vulnerabilities.pipelines.v2_importers.apache_httpd_importer import fetch_links
from vulnerabilities.pipelines.v2_importers.apache_httpd_importer import get_weaknesses

from django.conf import settings

# Dummy responses
class DummyResponseContent:
    def __init__(self, content_bytes):
        self.content = content_bytes


class DummyResponseJSON:
    def __init__(self, json_data):
        self._json = json_data

    def json(self):
        return self._json


# Tests for fetch_links
@pytest.fixture(autouse=True)
def no_requests(monkeypatch):
    # Ensure other tests don't hit real HTTP
    monkeypatch.setattr(
        requests,
        "get",
        lambda url: (_ for _ in ()).throw(AssertionError(f"Unexpected HTTP GET call to {url}")),
    )


def test_fetch_links_filters_and_resolves(monkeypatch):
    html = """
    <html><body>
      <a href="advisory1.json">A1</a>
      <a href="/json/advisory2.json">A2</a>
      <a href="readme.txt">TXT</a>
    </body></html>
    """
    base_url = "https://example.com/base/"
    # Monkeypatch HTTP GET for HTML
    def fake_get(url):
        assert url == base_url
        
        assert "headers" in kwargs, "Headers were not passed!"
        assert kwargs["headers"]["User-Agent"] == settings.VC_USER_AGENT
        
        return DummyResponseContent(html.encode("utf-8"))

    monkeypatch.setattr(requests, "get", fake_get)
    links = fetch_links(base_url)
    assert len(links) == 2
    assert links == [
        "https://example.com/base/advisory1.json",
        "https://example.com/json/advisory2.json",
    ]


# Tests for get_weaknesses
def test_get_weaknesses_with_cna_structure():
    mock_data = {
        "containers": {"cna": {"problemTypes": [{"descriptions": [{"cweId": "CWE-125"}]}]}}
    }
    result = get_weaknesses(mock_data)
    assert result == [125]


def test_get_weaknesses_with_data_meta_structure():
    mock_data = {
        "CVE_data_meta": {"ID": "CVE-2020-0001"},
        "problemtype": {
            "problemtype_data": [
                {"description": [{"value": "CWE-190 Integer Overflow"}]},
                {"description": [{"value": "CWE-200 Some Issue"}]},
            ]
        },
    }
    result = get_weaknesses(mock_data)
    assert set(result) == {190, 200}


# Tests for ApacheHTTPDImporterPipeline
class DummyPipeline(ApacheHTTPDImporterPipeline):
    # Expose protected methods for testing
    pass


@pytest.fixture
def pipeline(monkeypatch):
    pipe = DummyPipeline()
    # Prevent real HTTP in fetch_links
    monkeypatch.setattr(
        "vulnerabilities.pipelines.v2_importers.apache_httpd_importer.fetch_links",
        lambda url: ["u1", "u2"],
    )
    return pipe


def test_advisories_count(monkeypatch, pipeline):
    # Should use mocked links
    count = pipeline.advisories_count()
    assert count == 2


def test_collect_advisories_and_to_advisory(monkeypatch, pipeline):
    # Prepare two dummy JSONs
    sample1 = {
        "CVE_data_meta": {"ID": "CVE-1"},
        "description": {"description_data": [{"lang": "eng", "value": "Test desc"}]},
        "impact": [{"other": "5.0"}],
        "affects": {"vendor": {"vendor_data": []}},
        "timeline": [],
    }
    sample2 = {
        "cveMetadata": {"cveId": "CVE-2"},
        "description": {"description_data": [{"lang": "eng", "value": "Other desc"}]},
        "impact": [{"other": "7.5"}],
        "affects": {"vendor": {"vendor_data": []}},
        "timeline": [],
    }
    # Monkeypatch requests.get to return JSON
    def fake_get(u):
        assert "headers" in kwargs, "Headers were not passed!"
        assert kwargs["headers"]["User-Agent"] == settings.VC_USER_AGENT
        
        if u == "u1":
            return DummyResponseJSON(sample1)
        elif u == "u2":
            return DummyResponseJSON(sample2)
        else:
            raise AssertionError(f"Unexpected URL {u}")

    monkeypatch.setattr(requests, "get", fake_get)
    advisories = list(pipeline.collect_advisories())
    assert len(advisories) == 2
    # Validate first advisory
    adv1 = advisories[0]
    assert isinstance(adv1, AdvisoryDataV2)
    assert adv1.advisory_id == "CVE-1"
    assert adv1.summary == "Test desc"
    assert adv1.severities and adv1.severities[0].value == "5.0"
    assert adv1.url.endswith("CVE-1.json")
    # Validate second advisory
    adv2 = advisories[1]
    assert adv2.advisory_id == "CVE-2"
    assert adv2.summary == "Other desc"
    assert adv2.severities[0].value == "7.5"


# Test version range conversion error
def test_to_version_ranges_unknown_comparator(pipeline):
    # version_data with bad comparator
    versions_data = [{"version_value": "1.0.0", "version_affected": "<>"}]
    fixed_versions = []
    with pytest.raises(ValueError):
        pipeline.to_version_ranges(versions_data, fixed_versions)
