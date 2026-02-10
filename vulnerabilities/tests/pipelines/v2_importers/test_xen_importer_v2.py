#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from unittest.mock import patch

import pytest
from dateutil.parser import parse as date_parse

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines.v2_importers.xen_importer import XenImporterPipeline

SAMPLE_XSA_JSON = [
    {
        "xsas": [
            {
                "xsa": 123,
                "title": "Sample Xen Advisory",
                "public_time": "2022-09-15T00:00:00Z",
                "cve": ["CVE-2022-12345"],
            },
            {
                "xsa": 456,
                "title": "Another Advisory",
                "public_time": "2023-01-01T00:00:00Z",
                "cve": [],
            },
        ]
    }
]


@pytest.fixture
def pipeline():
    return XenImporterPipeline()


@patch("vulnerabilities.pipelines.v2_importers.xen_importer.fetch_response")
def test_get_xsa_data(mock_fetch, pipeline):
    mock_fetch.return_value.json.return_value = SAMPLE_XSA_JSON
    data = pipeline.get_xsa_data()
    assert isinstance(data, list)
    assert "xsas" in data[0]


@patch("vulnerabilities.pipelines.v2_importers.xen_importer.fetch_response")
def test_advisories_count(mock_fetch, pipeline):
    mock_fetch.return_value.json.return_value = SAMPLE_XSA_JSON
    count = pipeline.advisories_count()
    assert count == 2


@patch("vulnerabilities.pipelines.v2_importers.xen_importer.fetch_response")
def test_collect_advisories(mock_fetch, pipeline):
    mock_fetch.return_value.json.return_value = SAMPLE_XSA_JSON
    advisories = list(pipeline.collect_advisories())

    assert len(advisories) == 2

    first = advisories[0]
    assert isinstance(first, AdvisoryDataV2)
    assert first.advisory_id == "XSA-123"
    assert first.aliases == ["CVE-2022-12345"]
    assert first.summary == "Sample Xen Advisory"
    assert isinstance(first.references[0], ReferenceV2)
    assert first.date_published == date_parse("2022-09-15T00:00:00Z")


def test_to_advisories_single(pipeline):
    xsa_sample = {
        "xsa": 999,
        "title": "Test Advisory",
        "public_time": "2021-07-01T00:00:00Z",
        "cve": ["CVE-2021-9999"],
    }

    results = list(pipeline.to_advisories(xsa_sample))
    assert len(results) == 1

    advisory = results[0]
    assert advisory.advisory_id == "XSA-999"
    assert advisory.aliases == ["CVE-2021-9999"]
    assert advisory.summary == "Test Advisory"
    assert advisory.date_published == date_parse("2021-07-01T00:00:00Z")
    assert advisory.original_advisory_text.startswith('{\n  "xsa"')


def test_to_advisories_missing_fields(pipeline):
    xsa_sample = {"xsa": None, "title": None, "public_time": "2020-01-01T00:00:00Z", "cve": []}

    results = list(pipeline.to_advisories(xsa_sample))
    advisory = results[0]

    assert advisory.advisory_id == "XSA-None"
    assert advisory.aliases == []
    assert advisory.summary == None
