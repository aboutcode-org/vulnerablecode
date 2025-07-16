#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import pytest
from unittest import mock

import yaml
from vulnerabilities.pipelines.v2_importers.oss_fuzz import OSSFuzzImporterPipeline
from vulnerabilities.importer import AdvisoryData


@pytest.mark.django_db
def test_collect_advisories_parses_yaml_correctly(tmp_path):
    advisory_path = tmp_path / "vulns" / "dummy_project"
    advisory_path.mkdir(parents=True)
    yaml_file = advisory_path / "CVE-2024-1234.yaml"

    advisory_dict = {
        "id": "CVE-2024-1234",
        "summary": "Some summary here",
        "affected": [
            {
                "package": {"name": "some-lib"},
                "versions": ["1.0.0"]
            }
        ]
    }
    yaml_file.write_text(yaml.dump(advisory_dict), encoding="utf-8")

    pipeline = OSSFuzzImporterPipeline()
    pipeline.vcs_response = mock.Mock()
    pipeline.vcs_response.dest_dir = tmp_path

    advisories = list(pipeline.collect_advisories())
    assert len(advisories) == 1
    assert advisories[0].advisory_id == "CVE-2024-1234"
    assert advisories[0].summary == "Some summary here"


@pytest.mark.django_db
def test_advisories_count(tmp_path):
    (tmp_path / "vulns" / "project").mkdir(parents=True)
    (tmp_path / "vulns" / "project" / "CVE-2023-0001.yaml").write_text("id: CVE-2023-0001")
    (tmp_path / "vulns" / "project" / "CVE-2023-0002.yaml").write_text("id: CVE-2023-0002")

    pipeline = OSSFuzzImporterPipeline()
    pipeline.vcs_response = mock.Mock()
    pipeline.vcs_response.dest_dir = tmp_path

    assert pipeline.advisories_count() == 2
