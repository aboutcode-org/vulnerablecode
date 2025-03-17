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
from datetime import datetime
from pathlib import Path
from unittest import mock

import pytest
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import GemVersionRange
from univers.versions import RubygemsVersion

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.improvers.valid_versions import GitHubBasicImprover
from vulnerabilities.pipelines.github_importer import GitHubAPIImporterPipeline
from vulnerabilities.pipelines.github_importer import get_cwes_from_github_advisory
from vulnerabilities.pipelines.github_importer import process_response
from vulnerabilities.tests.pipelines import TestLogger
from vulnerabilities.tests.util_tests import VULNERABLECODE_REGEN_TEST_FIXTURES as REGEN

TEST_DATA = Path(__file__).parent.parent / "test_data" / "github_api"


@pytest.mark.parametrize(
    "pkg_type", ["maven", "nuget", "gem", "golang", "composer", "pypi", "npm", "cargo"]
)
def test_process_response_github_importer(pkg_type, regen=REGEN):
    response_file = TEST_DATA / f"{pkg_type}.json"
    expected_file = TEST_DATA / f"{pkg_type}-expected.json"
    with open(response_file) as f:
        response = json.load(f)

    result = [data.to_dict() for data in process_response(resp=response, package_type=pkg_type)]

    if regen:
        with open(expected_file, "w") as f:
            json.dump(result, f, indent=2)
        expected = result
    else:
        with open(expected_file) as f:
            expected = json.load(f)

    assert result == expected


def test_process_response_with_empty_vulnaribilities():
    logger = TestLogger()
    list(
        process_response(
            {"data": {"securityVulnerabilities": {"edges": []}}},
            "maven",
            logger=logger.write,
        )
    )
    assert "No vulnerabilities found for package_type: 'maven'" in logger.getvalue()


def test_process_response_with_empty_vulnaribilities_2():
    logger = TestLogger()
    list(
        process_response(
            {"data": {"securityVulnerabilities": {"edges": [{"node": {}}, None]}}},
            "maven",
            logger=logger.write,
        )
    )
    assert "No node found" in logger.getvalue()


def test_github_importer_with_missing_credentials():
    with mock.patch.dict(os.environ, {}, clear=True):
        github_pipeline = GitHubAPIImporterPipeline()
        status, error = github_pipeline.execute()
        assert 1 == status
        assert (
            "Cannot call GitHub API without a token set in the GH_TOKEN environment variable."
            in error
        )


@mock.patch("vulnerabilities.utils._get_gh_response")
def test_github_importer_with_missing_credentials_2(mock_response):
    mock_response.return_value = {"message": "Bad credentials"}
    with mock.patch.dict(os.environ, {"GH_TOKEN": "FOOD"}, clear=True):
        github_pipeline = GitHubAPIImporterPipeline()
        status, error = github_pipeline.execute()
        assert 1 == status
        assert "Invalid GitHub token: Bad credentials" in error


def valid_versions():
    return [
        "5.2.4.1",
        "6.1.4.3",
        "6.0.2",
        "5.2.1",
        "6.0.3",
        "7.0.2",
        "6.1.4.6",
        "5.2.0.beta2",
        "6.0.0.beta3",
        "5.2.0.beta1",
        "5.2.4.4",
        "5.2.0",
        "6.1.3",
        "6.0.0",
        "5.2.3.rc1",
        "6.0.3.5",
        "5.2.6.2",
        "6.1.0.rc1",
        "5.2.7",
        "6.1.2.1",
        "7.0.0.rc3",
        "6.0.4.7",
        "5.2.1.rc1",
        "7.0.2.1",
        "6.1.4.4",
        "5.2.5",
        "5.2.4.5",
        "7.0.2.2",
        "6.0.3.7",
        "6.0.4.2",
        "6.0.2.2",
        "5.2.2.1",
        "6.1.4",
        "7.0.0.rc2",
        "6.0.0.beta2",
        "5.2.1.1",
        "6.1.4.5",
        "6.0.3.1",
        "6.0.4.1",
        "6.0.2.1",
        "5.2.6.1",
        "5.2.6.3",
        "6.1.5",
        "6.0.3.3",
        "6.0.3.2",
        "5.2.2.rc1",
        "6.0.1",
        "7.0.0.alpha1",
        "5.2.6",
        "6.1.3.2",
        "6.0.4.6",
        "6.1.0.rc2",
        "5.2.4.3",
        "7.0.1",
        "7.0.2.3",
        "6.0.4",
        "7.0.0.rc1",
        "6.1.2",
        "5.2.4.6",
        "5.2.3",
        "6.1.4.2",
        "6.0.3.6",
        "6.0.4.4",
        "7.0.0",
        "6.0.4.3",
        "6.0.0.rc2",
        "5.2.4.rc1",
        "0.1",
        "6.1.0",
        "6.0.1.rc1",
        "5.2.4.2",
        "6.0.0.beta1",
        "5.2.4",
        "6.0.4.5",
        "6.1.3.1",
        "7.0.0.alpha2",
        "6.1.1",
        "6.0.0.rc1",
        "5.2.0.rc2",
        "6.1.4.1",
        "6.1.4.7",
        "5.2.2",
        "6.0.2.rc1",
        "5.2.0.rc1",
        "6.0.3.4",
        "6.0.3.rc1",
        "6.0.2.rc2",
        "10.2.8",
        "10.2.1",
    ]


@mock.patch("vulnerabilities.improvers.valid_versions.GitHubBasicImprover.get_package_versions")
def test_github_improver(mock_response, regen=REGEN):
    advisory_data = AdvisoryData(
        aliases=["CVE-2022-21831", "GHSA-w749-p3v6-hccq"],
        summary="Possible code injection vulnerability in Rails / Active Storage",
        affected_packages=[
            AffectedPackage(
                package=PackageURL(
                    type="gem",
                    namespace=None,
                    name="activestorage",
                    version=None,
                    qualifiers={},
                    subpath=None,
                ),
                affected_version_range=GemVersionRange(
                    constraints=(
                        VersionConstraint(comparator=">=", version=RubygemsVersion(string="5.2.0")),
                        VersionConstraint(
                            comparator="<=", version=RubygemsVersion(string="5.2.6.2")
                        ),
                        VersionConstraint(comparator=">=", version=RubygemsVersion(string="6.0.1")),
                        VersionConstraint(
                            comparator="<=", version=RubygemsVersion(string="6.0.4.3")
                        ),
                    )
                ),
                fixed_version=None,
            ),
            AffectedPackage(
                package=PackageURL(
                    type="gem",
                    namespace=None,
                    name="activestorage",
                    version=None,
                    qualifiers={},
                    subpath=None,
                ),
                affected_version_range=GemVersionRange(
                    constraints=(
                        VersionConstraint(
                            comparator=">=", version=RubygemsVersion(string="10.2.0")
                        ),
                        VersionConstraint(
                            comparator="<=", version=RubygemsVersion(string="10.2.8")
                        ),
                    )
                ),
            ),
        ],
        references=[
            Reference(
                reference_id="",
                url="https://nvd.nist.gov/vuln/detail/CVE-2022-21831",
                severities=[],
            ),
            Reference(
                reference_id="",
                url="https://github.com/rails/rails/commit/0a72f7d670e9aa77a0bb8584cb1411ddabb7546e",
                severities=[],
            ),
            Reference(
                reference_id="",
                url="https://groups.google.com/g/rubyonrails-security/c/n-p-W1yxatI",
                severities=[],
            ),
            Reference(
                reference_id="",
                url="https://rubysec.com/advisories/CVE-2022-21831/",
                severities=[],
            ),
            Reference(
                reference_id="GHSA-w749-p3v6-hccq",
                url="https://github.com/advisories/GHSA-w749-p3v6-hccq",
                severities=[
                    VulnerabilitySeverity(
                        system=severity_systems.CVSS31_QUALITY,
                        value="HIGH",
                    )
                ],
            ),
        ],
        date_published=datetime.now(),
    )
    mock_response.return_value = list(valid_versions())
    improver = GitHubBasicImprover()
    expected_file = os.path.join(TEST_DATA, "inference-expected.json")

    result = [data.to_dict() for data in improver.get_inferences(advisory_data=advisory_data)]

    if regen:
        with open(expected_file, "w") as f:
            json.dump(result, f, indent=2)
        expected = result
    else:
        with open(expected_file) as f:
            expected = json.load(f)

    assert result == expected


@mock.patch("fetchcode.package_versions.get_response")
def test_get_package_versions(mock_response):
    with open(TEST_DATA.parent / "package_manager_data" / "pypi.json", "r") as f:
        mock_response.return_value = json.load(f)

    improver = GitHubBasicImprover()
    valid_versions = [
        "1.0.1",
        "1.0.2",
        "1.0.3",
        "1.0.4",
        "1.1",
        "1.1.1",
        "1.1.2",
        "1.1.3",
        "1.1.4",
        "1.10",
        "1.10.1",
        "1.10.2",
        "1.10.3",
        "1.10.4",
        "1.10.5",
        "1.10.6",
        "1.10.7",
        "1.10.8",
        "1.10a1",
        "1.10b1",
        "1.10rc1",
        "vulnerabilities",
    ]

    result = sorted(
        improver.get_package_versions(package_url=PackageURL(type="pypi", name="django"))
    )
    expected = sorted(valid_versions)
    assert result == expected


def test_get_cwes_from_github_advisory():
    assert get_cwes_from_github_advisory(
        {"cwes": {"nodes": [{"cweId": "CWE-502"}, {"cweId": "CWE-770"}]}}
    ) == [502, 770]
    assert get_cwes_from_github_advisory(
        {
            "cwes": {
                "nodes": [
                    {"cweId": "CWE-173"},
                    {"cweId": "CWE-200"},
                    {"cweId": "CWE-378"},
                    {"cweId": "CWE-732"},
                ]
            }
        }
    ) == [173, 200, 378, 732]
    assert get_cwes_from_github_advisory(
        {"cwes": {"nodes": [{"cweId": "CWE-11111111111"}, {"cweId": "CWE-200"}]}}  # invalid cwe-id
    ) == [200]
