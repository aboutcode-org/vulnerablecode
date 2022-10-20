#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os
from datetime import datetime
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
from vulnerabilities.importers.github import GitHubAPIImporter
from vulnerabilities.importers.github import GitHubBasicImprover
from vulnerabilities.importers.github import process_response
from vulnerabilities.utils import GitHubTokenError

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "github_api")


@pytest.mark.parametrize("pkg_type", ["maven", "nuget", "gem", "golang", "composer", "pypi"])
def test_process_response_github_importer(pkg_type, regen=False):
    response_file = os.path.join(TEST_DATA, f"{pkg_type}.json")
    expected_file = os.path.join(TEST_DATA, f"{pkg_type}-expected.json")
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


def test_process_response_with_empty_vulnaribilities(caplog):
    list(process_response({"data": {"securityVulnerabilities": {"edges": []}}}, "maven"))
    assert "No vulnerabilities found for package_type: 'maven'" in caplog.text


def test_process_response_with_empty_vulnaribilities_2(caplog):
    list(
        process_response(
            {"data": {"securityVulnerabilities": {"edges": [{"node": {}}, None]}}}, "maven"
        )
    )
    assert "No node found" in caplog.text


def test_github_importer_with_missing_credentials():
    with pytest.raises(GitHubTokenError) as e:
        with mock.patch.dict(os.environ, {}, clear=True):
            importer = GitHubAPIImporter()
            list(importer.advisory_data())


@mock.patch("vulnerabilities.utils._get_gh_response")
def test_github_importer_with_missing_credentials_2(mock_response):
    mock_response.return_value = {"message": "Bad credentials"}
    with pytest.raises(GitHubTokenError) as e:
        with mock.patch.dict(os.environ, {"GH_TOKEN": "FOOD"}, clear=True):
            importer = GitHubAPIImporter()
            list(importer.advisory_data())


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
    ]


@mock.patch("vulnerabilities.importers.github.GitHubBasicImprover.get_package_versions")
def test_github_improver(mock_response, regen=False):
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
            )
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


@mock.patch("vulnerabilities.package_managers.get_response")
def test_get_package_versions(mock_response):
    with open(os.path.join(BASE_DIR, "test_data", "package_manager_data", "pypi.json"), "r") as f:
        mock_response.return_value = json.load(f)

    improver = GitHubBasicImprover()
    valid_versions = {
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
    }
    assert (
        improver.get_package_versions(package_url=PackageURL(type="pypi", name="django"))
        == valid_versions
    )
    mock_response.return_value = None
    assert not improver.get_package_versions(package_url=PackageURL(type="gem", name="foo"))
    assert not improver.get_package_versions(package_url=PackageURL(type="pypi", name="foo"))

    assert PackageURL(type="gem", name="foo") in improver.versions_fetcher_by_purl
    assert PackageURL(type="pypi", name="django") in improver.versions_fetcher_by_purl
    assert PackageURL(type="pypi", name="foo") in improver.versions_fetcher_by_purl
