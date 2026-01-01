#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
from pathlib import Path

import pytest

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.pipelines.v2_importers.openssf_malicious_importer import (
    OpenSSFMaliciousImporterPipeline,
)


@pytest.fixture
def sample_malicious_advisory(tmp_path: Path):
    """Create a sample malicious package advisory in OSV format."""
    advisory_data = {
        "modified": "2025-03-28T13:05:11Z",
        "published": "2025-03-28T13:05:11Z",
        "schema_version": "1.5.0",
        "id": "MAL-2025-1234",
        "summary": "Malicious code in malicious-test-package (PyPI)",
        "details": "This package contains malicious code that exfiltrates data.",
        "affected": [
            {
                "package": {
                    "ecosystem": "PyPI",
                    "name": "malicious-test-package",
                    "purl": "pkg:pypi/malicious-test-package",
                },
                "versions": ["0.0.1", "0.0.2"],
            }
        ],
        "credits": [
            {
                "name": "Security Researcher",
                "type": "FINDER",
                "contact": ["https://example.com"],
            }
        ],
        "database_specific": {
            "malicious-packages-origins": [
                {
                    "id": "TEST-2025-01234",
                    "import_time": "2025-03-31T07:07:04.129197674Z",
                    "modified_time": "2025-03-28T13:05:11Z",
                    "sha256": "abc123def456",
                    "source": "test-source",
                    "versions": ["0.0.1", "0.0.2"],
                }
            ]
        },
    }

    advisory_dir = tmp_path / "osv" / "malicious" / "pypi" / "malicious-test-package"
    advisory_dir.mkdir(parents=True)

    advisory_file = advisory_dir / "MAL-2025-1234.json"
    advisory_file.write_text(json.dumps(advisory_data, indent=2))

    return tmp_path, advisory_file.read_text(), advisory_data


@pytest.fixture
def sample_npm_malicious_advisory(tmp_path: Path):
    """Create a sample npm malicious package advisory."""
    advisory_data = {
        "modified": "2025-01-15T10:00:00Z",
        "published": "2025-01-15T10:00:00Z",
        "schema_version": "1.5.0",
        "id": "MAL-2025-5678",
        "summary": "Malicious code in typosquat-package (npm)",
        "details": "Typosquatting attack targeting popular package.",
        "affected": [
            {
                "package": {
                    "ecosystem": "npm",
                    "name": "typosquat-package",
                },
                "versions": ["1.0.0"],
            }
        ],
    }

    advisory_dir = tmp_path / "osv" / "malicious" / "npm" / "typosquat-package"
    advisory_dir.mkdir(parents=True)

    advisory_file = advisory_dir / "MAL-2025-5678.json"
    advisory_file.write_text(json.dumps(advisory_data, indent=2))

    return tmp_path, advisory_file.read_text(), advisory_data


class DummyVCSResponse:
    """Mock VCS response for testing."""

    def __init__(self, dest_dir):
        self.dest_dir = dest_dir

    def delete(self):
        pass


def test_collect_advisories_from_openssf_malicious(sample_malicious_advisory):
    """Test collecting advisories from OpenSSF malicious packages repo."""
    tmp_path, advisory_text, advisory_json = sample_malicious_advisory

    importer = OpenSSFMaliciousImporterPipeline()
    importer.vcs_response = DummyVCSResponse(str(tmp_path))

    advisories = list(importer.collect_advisories())
    assert len(advisories) == 1

    advisory = advisories[0]
    assert isinstance(advisory, AdvisoryData)
    assert advisory.advisory_id == "MAL-2025-1234"
    assert "Malicious code" in advisory.summary
    assert advisory.original_advisory_text.strip().startswith("{")
    assert advisory.affected_packages
    assert advisory.affected_packages[0].package.type == "pypi"
    assert advisory.affected_packages[0].package.name == "malicious-test-package"


def test_collect_npm_advisories(sample_npm_malicious_advisory):
    """Test collecting npm malicious package advisories."""
    tmp_path, advisory_text, advisory_json = sample_npm_malicious_advisory

    importer = OpenSSFMaliciousImporterPipeline()
    importer.vcs_response = DummyVCSResponse(str(tmp_path))

    advisories = list(importer.collect_advisories())
    assert len(advisories) == 1

    advisory = advisories[0]
    assert advisory.advisory_id == "MAL-2025-5678"
    assert advisory.affected_packages[0].package.type == "npm"
    assert advisory.affected_packages[0].package.name == "typosquat-package"


def test_advisories_count(sample_malicious_advisory):
    """Test counting advisories."""
    tmp_path, _, _ = sample_malicious_advisory

    importer = OpenSSFMaliciousImporterPipeline()
    importer.vcs_response = DummyVCSResponse(str(tmp_path))

    count = importer.advisories_count()
    assert count == 1


def test_multiple_advisories(tmp_path: Path):
    """Test collecting multiple advisories from different ecosystems."""
    # Create PyPI advisory
    pypi_dir = tmp_path / "osv" / "malicious" / "pypi" / "bad-pkg"
    pypi_dir.mkdir(parents=True)
    (pypi_dir / "MAL-2025-0001.json").write_text(
        json.dumps(
            {
                "id": "MAL-2025-0001",
                "summary": "Bad PyPI package",
                "affected": [{"package": {"ecosystem": "PyPI", "name": "bad-pkg"}, "versions": ["1.0"]}],
            }
        )
    )

    # Create npm advisory
    npm_dir = tmp_path / "osv" / "malicious" / "npm" / "bad-js"
    npm_dir.mkdir(parents=True)
    (npm_dir / "MAL-2025-0002.json").write_text(
        json.dumps(
            {
                "id": "MAL-2025-0002",
                "summary": "Bad npm package",
                "affected": [{"package": {"ecosystem": "npm", "name": "bad-js"}, "versions": ["2.0"]}],
            }
        )
    )

    importer = OpenSSFMaliciousImporterPipeline()
    importer.vcs_response = DummyVCSResponse(str(tmp_path))

    advisories = list(importer.collect_advisories())
    assert len(advisories) == 2
    assert importer.advisories_count() == 2

    advisory_ids = {a.advisory_id for a in advisories}
    assert advisory_ids == {"MAL-2025-0001", "MAL-2025-0002"}


def test_pipeline_metadata():
    """Test pipeline metadata is correctly set."""
    assert OpenSSFMaliciousImporterPipeline.pipeline_id == "openssf_malicious_importer"
    assert OpenSSFMaliciousImporterPipeline.spdx_license_expression == "Apache-2.0"
    assert "ossf/malicious-packages" in OpenSSFMaliciousImporterPipeline.repo_url


def test_unsupported_ecosystem_skipped(tmp_path: Path):
    """Test that unsupported ecosystems are skipped gracefully."""
    # Create advisory with unsupported ecosystem
    advisory_dir = tmp_path / "osv" / "malicious" / "unsupported" / "pkg"
    advisory_dir.mkdir(parents=True)
    (advisory_dir / "MAL-2025-9999.json").write_text(
        json.dumps(
            {
                "id": "MAL-2025-9999",
                "summary": "Package in unsupported ecosystem",
                "affected": [
                    {"package": {"ecosystem": "UnsupportedEcosystem", "name": "pkg"}, "versions": ["1.0"]}
                ],
            }
        )
    )

    importer = OpenSSFMaliciousImporterPipeline()
    importer.vcs_response = DummyVCSResponse(str(tmp_path))

    advisories = list(importer.collect_advisories())
    # Advisory should be yielded but with no affected packages due to unsupported ecosystem
    assert len(advisories) == 1
    assert advisories[0].affected_packages == []
