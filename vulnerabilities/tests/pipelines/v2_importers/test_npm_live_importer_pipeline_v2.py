#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import NpmVersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.pipelines.v2_importers.npm_live_importer import NpmLiveImporterPipeline

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "npm"


def test_package_first_mode_valid_npm_package(tmp_path):
    vuln_dir = tmp_path / "vuln" / "npm"
    vuln_dir.mkdir(parents=True)

    npm_sample_file = os.path.join(TEST_DATA, "npm_sample.json")
    with open(npm_sample_file) as f:
        sample_data = json.load(f)

    advisory_file = vuln_dir / "152.json"
    advisory_file.write_text(json.dumps(sample_data))

    mock_vcs_response = SimpleNamespace(dest_dir=str(tmp_path), delete=lambda: None)

    purl = PackageURL(type="npm", name="npm", version="1.2.0")
    pipeline = NpmLiveImporterPipeline(purl=purl)
    pipeline.vcs_response = mock_vcs_response

    pipeline.get_purl_inputs()
    advisories = list(pipeline.collect_advisories())

    assert len(advisories) == 1
    assert advisories[0].aliases == ["CVE-2013-4116"]
    assert len(advisories[0].affected_packages) == 1
    assert advisories[0].affected_packages[0].package.name == "npm"


def test_package_first_mode_unaffected_version(tmp_path):
    vuln_dir = tmp_path / "vuln" / "npm"
    vuln_dir.mkdir(parents=True)

    npm_sample_file = os.path.join(TEST_DATA, "npm_sample.json")
    with open(npm_sample_file) as f:
        sample_data = json.load(f)

    advisory_file = vuln_dir / "152.json"
    advisory_file.write_text(json.dumps(sample_data))

    mock_vcs_response = SimpleNamespace(dest_dir=str(tmp_path), delete=lambda: None)

    purl = PackageURL(type="npm", name="npm", version="1.4.0")
    pipeline = NpmLiveImporterPipeline(purl=purl)
    pipeline.vcs_response = mock_vcs_response

    pipeline.get_purl_inputs()
    advisories = list(pipeline.collect_advisories())

    assert len(advisories) == 0


def test_package_first_mode_invalid_package_type(tmp_path):
    vuln_dir = tmp_path / "vuln" / "npm"
    vuln_dir.mkdir(parents=True)

    mock_vcs_response = SimpleNamespace(dest_dir=str(tmp_path), delete=lambda: None)

    purl = PackageURL(type="pypi", name="django", version="3.0.0")
    pipeline = NpmLiveImporterPipeline(purl=purl)
    pipeline.vcs_response = mock_vcs_response

    with pytest.raises(ValueError):
        pipeline.get_purl_inputs()


def test_package_first_mode_package_not_found(tmp_path):
    vuln_dir = tmp_path / "vuln" / "npm"
    vuln_dir.mkdir(parents=True)

    npm_sample_file = os.path.join(TEST_DATA, "npm_sample.json")
    with open(npm_sample_file) as f:
        sample_data = json.load(f)

    sample_data["module_name"] = "some-other-package"

    advisory_file = vuln_dir / "152.json"
    advisory_file.write_text(json.dumps(sample_data))

    mock_vcs_response = SimpleNamespace(dest_dir=str(tmp_path), delete=lambda: None)

    purl = PackageURL(type="npm", name="nonexistent-package", version="1.0.0")
    pipeline = NpmLiveImporterPipeline(purl=purl)
    pipeline.vcs_response = mock_vcs_response

    pipeline.get_purl_inputs()
    advisories = list(pipeline.collect_advisories())

    assert len(advisories) == 0


def test_version_is_affected():
    purl = PackageURL(type="npm", name="npm", version="1.2.0")
    pipeline = NpmLiveImporterPipeline(purl=purl)
    pipeline.get_purl_inputs()

    affected_package = AffectedPackageV2(
        package=PackageURL(type="npm", name="npm"),
        affected_version_range=NpmVersionRange(
            constraints=(VersionConstraint(comparator="<", version=SemverVersion(string="1.3.3")),)
        ),
    )

    assert pipeline._version_is_affected(affected_package) == True

    pipeline.purl = PackageURL(type="npm", name="npm", version="1.4.0")
    assert pipeline._version_is_affected(affected_package) == False

    pipeline.purl = PackageURL(type="npm", name="npm")
    assert pipeline._version_is_affected(affected_package) == True
