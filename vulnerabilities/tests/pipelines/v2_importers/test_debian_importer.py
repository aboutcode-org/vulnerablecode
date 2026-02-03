#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from packageurl import PackageURL
from univers.version_range import DebianVersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines.v2_importers.debian_importer import DebianImporterPipeline
from vulnerabilities.pipelines.v2_importers.debian_importer import get_cwe_from_debian_advisory


@pytest.fixture
def importer():
    return DebianImporterPipeline()


@pytest.fixture
def sample_response():
    return {
        "openssl": {
            "CVE-2023-1234": {
                "description": "Some vulnerability description (CWE-79)",
                "debianbug": 123456,
                "releases": {
                    "bullseye": {
                        "status": "resolved",
                        "repositories": {"bullseye": "1.1.1k-1"},
                        "fixed_version": "1.1.1k-2",
                    },
                    "bookworm": {
                        "status": "open",
                        "repositories": {"bookworm": "1.1.1l-1"},
                    },
                },
            }
        }
    }


def test_get_cwe_from_debian_advisory_with_cwe():
    record = {"description": "This issue relates to improper input validation (CWE-20)."}

    weaknesses = get_cwe_from_debian_advisory(record)

    assert len(weaknesses) == 1
    assert weaknesses[0] == 20


def test_get_cwe_from_debian_advisory_without_cwe():
    record = {"description": "No weakness mentioned here."}

    weaknesses = get_cwe_from_debian_advisory(record)

    assert weaknesses == []


@patch("vulnerabilities.pipelines.v2_importers.debian_importer.fetch_response")
def test_get_response_success(mock_fetch, importer, sample_response):
    mock_resp = MagicMock()
    mock_resp.json.return_value = sample_response
    mock_fetch.return_value = mock_resp

    response = importer.get_response()

    assert response == sample_response
    mock_fetch.assert_called_once_with(importer.api_url)


@patch("vulnerabilities.pipelines.v2_importers.debian_importer.fetch_response")
def test_get_response_failure(mock_fetch, importer):
    mock_fetch.side_effect = Exception("network error")

    response = importer.get_response()

    assert response == {}


def test_advisories_count(importer, sample_response):
    importer.response = sample_response

    count = importer.advisories_count()

    assert count == 1


def test_collect_advisories(importer, sample_response):
    importer.response = sample_response

    advisories = list(importer.collect_advisories())

    assert len(advisories) == 1
    advisory = advisories[0]

    assert isinstance(advisory, AdvisoryData)
    assert advisory.advisory_id == "openssl/CVE-2023-1234"
    assert advisory.summary.startswith("Some vulnerability")


def test_affected_packages_generation(importer, sample_response):
    importer.response = sample_response

    advisory = next(importer.collect_advisories())
    affected_packages = advisory.affected_packages

    assert len(affected_packages) == 2

    for pkg in affected_packages:
        assert isinstance(pkg, AffectedPackageV2)
        assert isinstance(pkg.package, PackageURL)
        assert isinstance(pkg.fixed_version_range, DebianVersionRange)


def test_debian_bug_reference(importer, sample_response):
    importer.response = sample_response

    advisory = next(importer.collect_advisories())
    references = advisory.references

    assert len(references) == 1
    ref = references[0]

    assert isinstance(ref, ReferenceV2)
    assert ref.reference_id == "123456"
    assert "bugs.debian.org" in ref.url
