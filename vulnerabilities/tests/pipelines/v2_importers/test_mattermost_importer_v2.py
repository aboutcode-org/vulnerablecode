#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest
from packageurl import PackageURL
from univers.version_range import GitHubVersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.pipelines.v2_importers.mattermost_importer import MattermostImporterPipeline


@pytest.fixture
def sample_mattermost_data():
    return [
        {
            "issue_id": "MMSA-2024-001",
            "cve_id": "CVE-2024-1234",
            "details": "Test vulnerability in Mattermost Server",
            "platform": "Mattermost Server",
            "severity": "HIGH",
            "fix_versions": ["v9.0.1", "v8.1.5"],
        }
    ]


@pytest.fixture
def importer(monkeypatch, sample_mattermost_data):
    """
    Create an importer with fetch_response mocked.
    """

    def mock_fetch_response(url):
        class MockResponse:
            def json(self_inner):
                return sample_mattermost_data

        return MockResponse()

    monkeypatch.setattr(
        "vulnerabilities.pipelines.v2_importers.mattermost_importer.fetch_response",
        mock_fetch_response,
    )

    return MattermostImporterPipeline()


def test_advisories_count(importer):
    assert importer.advisories_count() == 1


def test_collect_advisories_happy_path(importer):
    advisories = list(importer.collect_advisories())

    assert len(advisories) == 1
    advisory = advisories[0]

    assert isinstance(advisory, AdvisoryData)
    assert advisory.advisory_id == "MMSA-2024-001"
    assert advisory.aliases == ["CVE-2024-1234"]
    assert "Test vulnerability" in advisory.summary

    assert advisory.affected_packages
    affected = advisory.affected_packages[0]

    assert affected.package == PackageURL(
        type="github",
        namespace="mattermost",
        name="mattermost-server",
    )

    assert isinstance(affected.fixed_version_range, GitHubVersionRange)
    assert str(affected.fixed_version_range) == "vers:github/8.1.5|9.0.1"


def test_skip_invalid_issue_id(monkeypatch):
    data = [
        {
            "issue_id": "INVALID-001",
            "platform": "Mattermost Server",
        }
    ]

    def mock_fetch_response(url):
        class MockResponse:
            def json(self):
                return data

        return MockResponse()

    monkeypatch.setattr(
        "vulnerabilities.pipelines.v2_importers.mattermost_importer.fetch_response",
        mock_fetch_response,
    )

    importer = MattermostImporterPipeline()
    advisories = list(importer.collect_advisories())

    assert advisories == []


def test_unknown_platform(monkeypatch):
    data = [
        {
            "issue_id": "MMSA-2024-002",
            "platform": "Unknown Product",
            "fix_versions": ["1.0.0"],
        }
    ]

    def mock_fetch_response(url):
        class MockResponse:
            def json(self):
                return data

        return MockResponse()

    monkeypatch.setattr(
        "vulnerabilities.pipelines.v2_importers.mattermost_importer.fetch_response",
        mock_fetch_response,
    )

    importer = MattermostImporterPipeline()
    advisories = list(importer.collect_advisories())

    assert len(advisories) == 1
    assert advisories[0].affected_packages == []


def test_fixed_version_string_normalization(monkeypatch):
    data = [
        {
            "issue_id": "MMSA-2024-003",
            "platform": "Mattermost Desktop App",
            "fix_versions": "v2.0.0",
        }
    ]

    def mock_fetch_response(url):
        class MockResponse:
            def json(self):
                return data

        return MockResponse()

    monkeypatch.setattr(
        "vulnerabilities.pipelines.v2_importers.mattermost_importer.fetch_response",
        mock_fetch_response,
    )

    importer = MattermostImporterPipeline()
    advisories = list(importer.collect_advisories())

    affected = advisories[0].affected_packages[0]
    assert "2.0.0" in str(affected.fixed_version_range)


def test_bad_version_does_not_crash(monkeypatch):
    data = [
        {
            "issue_id": "MMSA-2024-004",
            "platform": "Mattermost Server",
            "fix_versions": ["not-a-version"],
        }
    ]

    def mock_fetch_response(url):
        class MockResponse:
            def json(self):
                return data

        return MockResponse()

    monkeypatch.setattr(
        "vulnerabilities.pipelines.v2_importers.mattermost_importer.fetch_response",
        mock_fetch_response,
    )

    importer = MattermostImporterPipeline()
    advisories = list(importer.collect_advisories())

    # Advisory should still be yielded, but without affected packages
    assert len(advisories) == 1
    assert advisories[0].affected_packages == []


def test_fetch_is_cached(monkeypatch):
    call_count = {"count": 0}

    def mock_fetch_response(url):
        call_count["count"] += 1

        class MockResponse:
            def json(self):
                return []

        return MockResponse()

    monkeypatch.setattr(
        "vulnerabilities.pipelines.v2_importers.mattermost_importer.fetch_response",
        mock_fetch_response,
    )

    importer = MattermostImporterPipeline()
    importer.advisories_count()
    importer.collect_advisories()

    assert call_count["count"] == 1
