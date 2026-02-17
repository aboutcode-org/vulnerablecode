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
from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.pipelines.v2_importers.github_osv_importer import GithubOSVImporterPipeline


@pytest.fixture
def sample_osv_advisory(tmp_path: Path):
    advisory_data = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "summary": "Sample summary",
        "details": "Sample details",
        "aliases": ["CVE-2021-99999"],
        "affected": [
            {
                "package": {"name": "sample", "ecosystem": "pypi"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}]}
                ],
                "versions": ["1.0.0", "1.1.0"],
            }
        ],
        "database_specific": {"cwe_ids": ["CWE-79"]},
    }

    advisory_dir = tmp_path / "advisories/github-reviewed/sample_project"
    advisory_dir.mkdir(parents=True)

    advisory_file = advisory_dir / "GHSA-xxxx-yyyy-zzzz.json"
    advisory_file.write_text(json.dumps(advisory_data, indent=2))

    return tmp_path, advisory_file.read_text(), advisory_data


def test_collect_advisories_from_github_osv(monkeypatch, sample_osv_advisory):
    tmp_path, advisory_text, advisory_json = sample_osv_advisory

    class DummyVCSResponse:
        dest_dir = str(tmp_path)

        def delete(self):
            pass

    importer = GithubOSVImporterPipeline()
    importer.vcs_response = DummyVCSResponse()

    advisories = list(importer.collect_advisories())
    assert len(advisories) == 1

    advisory = advisories[0]
    assert isinstance(advisory, AdvisoryDataV2)
    assert advisory.advisory_id == "GHSA-xxxx-yyyy-zzzz"
    assert "CVE-2021-99999" in advisory.aliases
    assert advisory.summary.startswith("Sample")
    assert advisory.original_advisory_text.strip().startswith("{")
    assert advisory.affected_packages
    assert advisory.affected_packages[0].package.type == "pypi"
