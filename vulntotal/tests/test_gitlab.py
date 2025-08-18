# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path
from unittest import mock

from commoncode import testcase
from packageurl import PackageURL

from vulnerabilities.tests import util_tests
from vulntotal.datasources import gitlab
from vulntotal.datasources import gitlab_api


class TestGitlab(testcase.FileBasedTesting):
    test_data_dir = str(Path(__file__).resolve().parent / "test_data" / "gitlab")

    def test_generate_package_advisory_url(self):
        purls = [
            "pkg:pypi/jinja2@2.4.1",
            "pkg:maven/org.apache.tomcat/tomcat@10.1.0",
            "pkg:npm/semver-regex@3.1.3",
            "pkg:golang/github.com/mattermost/mattermost-server/v6/api4@0.1",
            "pkg:composer/bolt/core@0.1",
            "pkg:nuget/moment.js@2.18.0",
        ]
        supported_ecosystem = gitlab.GitlabDataSource.supported_ecosystem()
        results = [
            gitlab_api.get_package_slug(PackageURL.from_string(purl), supported_ecosystem)
            for purl in purls
        ]
        expected_file = self.get_test_loc("package_advisory_url-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)

    @mock.patch("vulntotal.datasources.gitlab_api.fetch_yaml")
    @mock.patch("vulntotal.datasources.gitlab_api.fetch_directory_contents")
    def test_parse_interesting_advisories(self, mock_fetch_directory_contents, mock_fetch_yaml):
        # Mock the directory contents response
        mock_fetch_directory_contents.return_value = [
            {"name": "CVE-2014-1402.yml", "path": "path/to/CVE-2014-1402.yml"},
            {"name": "CVE-2016-10745.yml", "path": "path/to/CVE-2016-10745.yml"},
            {"name": "CVE-2019-10906.yml", "path": "path/to/CVE-2019-10906.yml"},
            {"name": "CVE-2019-8341.yml", "path": "path/to/CVE-2019-8341.yml"},
            {"name": "CVE-2020-28493.yml", "path": "path/to/CVE-2020-28493.yml"},
        ]

        # Mock the yaml file responses
        advisory_folder = (
            Path(__file__)
            .resolve()
            .parent.joinpath(
                "test_data/gitlab/temp_vulntotal_gitlab_datasource/gemnasium-db-master-pypi-Jinja2/pypi/Jinja2"
            )
        )
        yaml_files = []
        sorted_files = sorted(advisory_folder.iterdir(), key=lambda x: x.name)
        for file in sorted_files:
            if file.suffix == ".yml":
                with open(file, "r") as f:
                    yaml_files.append(f.read())

        mock_fetch_yaml.side_effect = yaml_files

        purl = PackageURL("pypi", "namespace", "test", "0.1.1")

        supported_ecosystem = gitlab.GitlabDataSource.supported_ecosystem()

        advisories = gitlab_api.fetch_gitlab_advisories_for_purl(
            purl, supported_ecosystem, gitlab.get_casesensitive_slug
        )

        results = [adv.to_dict() for adv in gitlab.parse_interesting_advisories(advisories, purl)]

        expected_file = self.get_test_loc("parsed_advisory-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)
