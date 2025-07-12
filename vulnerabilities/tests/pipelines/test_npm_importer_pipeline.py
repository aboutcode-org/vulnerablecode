#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

# Author: Navonil Das (@NavonilDas)

import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import NpmVersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.improvers.valid_versions import NpmImprover
from vulnerabilities.pipelines.npm_importer import NpmImporterPipeline
from vulnerabilities.tests import util_tests
from vulnerabilities.utils import load_json

TEST_DATA = data = Path(__file__).parent.parent / "test_data" / "npm"


def test_npm_importer():
    file = os.path.join(TEST_DATA, "npm_sample.json")
    result = [adv.to_dict() for adv in NpmImporterPipeline().to_advisory_data(file=file)]
    expected_file = os.path.join(TEST_DATA, f"parse-advisory-npm-expected.json")
    util_tests.check_results_against_json(result, expected_file)


def test_get_affected_package():
    file = os.path.join(TEST_DATA, "npm_sample.json")
    data = load_json(file)
    assert AffectedPackage(
        package=PackageURL(
            type="npm", namespace=None, name="npm", version=None, qualifiers={}, subpath=None
        ),
        affected_version_range=NpmVersionRange(
            constraints=(VersionConstraint(comparator="<", version=SemverVersion(string="1.3.3")),)
        ),
        fixed_version=SemverVersion(string="1.3.3"),
    ) == NpmImporterPipeline().get_affected_package(data, "npm")


@patch("vulnerabilities.improvers.valid_versions.NpmImprover.get_package_versions")
def test_npm_improver(mock_response):
    advisory_file = os.path.join(TEST_DATA, f"parse-advisory-npm-expected.json")
    with open(advisory_file) as exp:
        advisories = [AdvisoryData.from_dict(adv) for adv in (json.load(exp))]
    mock_response.return_value = [
        "0.1.0",
        "0.5.6",
        "0.5.2",
        "1.1.1",
        "1.1.2",
        "1.1.3",
        "1.1.4",
        "1.1.5",
        "1.1.6",
        "1.1.7",
        "1.1.8",
    ]
    improvers = [NpmImprover(), DefaultImprover()]
    result = []
    for improver in improvers:
        for advisory in advisories:
            inference = [data.to_dict() for data in improver.get_inferences(advisory)]
            result.extend(inference)
    expected_file = os.path.join(TEST_DATA, f"npm-improver-expected.json")
    util_tests.check_results_against_json(result, expected_file)


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
    pipeline = NpmImporterPipeline(purl=purl)
    pipeline.vcs_response = mock_vcs_response

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
    pipeline = NpmImporterPipeline(purl=purl)
    pipeline.vcs_response = mock_vcs_response

    advisories = list(pipeline.collect_advisories())

    assert len(advisories) == 0


def test_package_first_mode_invalid_package_type(tmp_path):
    vuln_dir = tmp_path / "vuln" / "npm"
    vuln_dir.mkdir(parents=True)

    mock_vcs_response = SimpleNamespace(dest_dir=str(tmp_path), delete=lambda: None)

    purl = PackageURL(type="pypi", name="django", version="3.0.0")
    pipeline = NpmImporterPipeline(purl=purl)
    pipeline.vcs_response = mock_vcs_response

    advisories = list(pipeline.collect_advisories())

    assert len(advisories) == 0


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
    pipeline = NpmImporterPipeline(purl=purl)
    pipeline.vcs_response = mock_vcs_response

    advisories = list(pipeline.collect_advisories())

    assert len(advisories) == 0


def test_package_first_mode_missing_vuln_directory(tmp_path):
    mock_vcs_response = SimpleNamespace(dest_dir=str(tmp_path), delete=lambda: None)

    purl = PackageURL(type="npm", name="npm", version="1.0.0")
    pipeline = NpmImporterPipeline(purl=purl)
    pipeline.vcs_response = mock_vcs_response

    advisories = list(pipeline.collect_advisories())

    assert len(advisories) == 0


def test_version_is_affected():
    purl = PackageURL(type="npm", name="npm", version="1.2.0")
    pipeline = NpmImporterPipeline(purl=purl)

    affected_package = AffectedPackage(
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

    affected_package_no_range = AffectedPackage(
        package=PackageURL(type="npm", name="npm"),
        affected_version_range=None,
        fixed_version=SemverVersion(string="1.3.3"),
    )
    assert pipeline._version_is_affected(affected_package_no_range) == True
    affected_package_no_range = AffectedPackage(
        package=PackageURL(type="npm", name="npm"),
        affected_version_range=None,
        fixed_version=SemverVersion(string="1.3.3"),
    )
    assert pipeline._version_is_affected(affected_package_no_range) == True
