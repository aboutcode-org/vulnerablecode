# Author: Navonil Das (@NavonilDas)
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
import shutil
import tempfile
import zipfile
from unittest.mock import patch

from django.test import TestCase
from univers.versions import SemverVersion

from vulnerabilities import models
from vulnerabilities.import_runner import ImportRunner
from vulnerabilities.importers.npm import categorize_versions
from vulnerabilities.importers.npm import normalize_ranges
from vulnerabilities.package_managers import NpmVersionAPI
from vulnerabilities.package_managers import PackageVersion

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/")


# MOCK_VERSION_API = NpmVersionAPI(
#     cache={
#         "jquery": {Version("3.4.0"), Version("3.8.0")},
#         "kerberos": {Version("0.5.8"), Version("1.2.0")},
#         "@hapi/subtext": {
#             Version("3.7.0"),
#             Version("4.1.1"),
#             Version("6.1.3"),
#             Version("7.0.0"),
#             Version("7.0.5"),
#         },
#     }
# )

#
# @patch ( "vulnerabilities.importers.NpmImporter._update_from_remote" )
class NpmImportTest(TestCase):
    tempdir = None
    #
    # @classmethod
    # def setUpClass( cls ) -> None :
    #     cls.tempdir = tempfile.mkdtemp ()
    #     zip_path = os.path.join ( TEST_DATA, "npm.zip" )
    #
    #     with zipfile.ZipFile ( zip_path, "r" ) as zip_ref :
    #         zip_ref.extractall ( cls.tempdir )
    #
    #     cls.importer = models.Importer.objects.create (
    #         name="npm_unittests",
    #         license="",
    #         last_run=None,
    #         data_source="NpmImporter",
    #         data_source_cfg={
    #             "repository_url": "https://example.git",
    #             "working_directory": os.path.join(cls.tempdir, "npm/npm_test"),
    #             "create_working_directory": False,
    #             "remove_working_directory": False,
    #         },
    #     )

    # @classmethod
    # def tearDownClass( cls ) -> None :
    #     # Make sure no requests for unexpected package names have been made during the tests.
    #     shutil.rmtree ( cls.tempdir )
    #     assert len ( MOCK_VERSION_API.cache ) == 3, MOCK_VERSION_API.cache
    #
    # def test_import( self, _ ) :
    #     runner = ImportRunner ( self.importer, 5 )
    #
    #     with patch ( "vulnerabilities.importers.NpmImporter.versions", new=MOCK_VERSION_API ) :
    #         with patch ( "vulnerabilities.importers.NpmImporter.set_api" ) :
    #             runner.run ()
    #
    #     assert models.Vulnerability.objects.count () == 3
    #     assert models.VulnerabilityReference.objects.count () == 3
    #     assert models.PackageRelatedVulnerability.objects.all ().count () == 4
    #
    #     assert models.Package.objects.count () == 8
    #
    #     self.assert_for_package (
    #         "jquery", {"3.4.0"}, {"3.8.0"}, "1518", vulnerability_id="CVE-2020-11022"
    #     )  # nopep8
    #     self.assert_for_package ( "kerberos", {"0.5.8"}, {"1.2.0"}, "1514" )
    #     self.assert_for_package ( "subtext", {"4.1.1", "7.0.0"}, {"6.1.3", "7.0.5"}, "1476" )
    #
    # def assert_for_package(
    #         self,
    #         package_name,
    #         impacted_versions,
    #         resolved_versions,
    #         vuln_id,
    #            vulnerability_id=None,
    # ) :
    #     vuln = None
    #
    #     for version in impacted_versions :
    #         pkg = models.Package.objects.get ( name=package_name, version=version )
    #
    #         assert pkg.vulnerabilities.count () == 1
    #         vuln = pkg.vulnerabilities.first ()
    #         if vulnerability_id :
    #             assert vuln.vulnerability_id == vulnerability_id
    #
    #         ref_url = f"https://registry.npmjs.org/-/npm/v1/advisories/{vuln_id}"
    #         assert models.VulnerabilityReference.objects.get ( url=ref_url, vulnerability=vuln )
    #
    #     for version in resolved_versions :
    #         pkg = models.Package.objects.get ( name=package_name, version=version )
    #         assert models.PackageRelatedVulnerability.objects.filter (
    #             patched_package=pkg, vulnerability=vuln
    #         )


def test_categorize_versions_simple_ranges():
    all_versions = {PackageVersion("3.4.0"), PackageVersion("3.8.0")}
    impacted_ranges = "<3.5.0"
    resolved_ranges = ">=3.5.0"

    impacted_versions, resolved_versions = categorize_versions(
        all_versions, impacted_ranges, resolved_ranges
    )

    assert impacted_versions == {SemverVersion("3.4.0")}
    assert resolved_versions == {SemverVersion("3.8.0")}


def test_categorize_versions_complex_ranges():
    all_versions = {
        PackageVersion("3.7.0"),
        PackageVersion("4.1.1"),
        PackageVersion("6.1.3"),
        PackageVersion("7.0.0"),
        PackageVersion("7.0.5"),
    }
    impacted_ranges = ">=4.1.0 <6.1.3 || >= 7.0.0 <7.0.3"
    resolved_ranges = ">=6.1.3 <7.0.0 || >=7.0.3"

    impacted_versions, resolved_versions = categorize_versions(
        all_versions, impacted_ranges, resolved_ranges
    )

    assert impacted_versions == {SemverVersion("4.1.1"), SemverVersion("7.0.0")}
    assert resolved_versions == {
        SemverVersion("3.7.0"),
        SemverVersion("6.1.3"),
        SemverVersion("7.0.5"),
    }


def test_normalize_ranges():
    assert normalize_ranges(">=6.1.3 < 7.0.0 || >=7.0.3") == [">=6.1.3,<7.0.0", ">=7.0.3"]
    assert normalize_ranges(">=4.1.0 <6.1.3 || >= 7.0.0 <7.0.3") == [
        ">=4.1.0,<6.1.3",
        ">=7.0.0,<7.0.3",
    ]
