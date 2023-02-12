#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import os
import pathlib
from unittest import TestCase
from unittest.mock import patch

from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Reference
from vulnerabilities.importers.ruby import RubyImporter
from vulnerabilities.package_managers import RubyVersionAPI
from vulnerabilities.package_managers import VersionResponse
from vulnerabilities.utils import AffectedPackage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "ruby")

MOCK_ADDED_FILES = []

for filepath in pathlib.Path(TEST_DATA).glob("**/*.yml"):
    MOCK_ADDED_FILES.append(filepath.absolute())


class RubyImporterTest(TestCase):
    @classmethod
    def setUpClass(cls):
        data_source_cfg = {
            "repository_url": "https://github.com/rubysec/ruby-advisory-db.git",
        }
        cls.data_src = RubyImporter(1, config=data_source_cfg)
        cls.data_src.pkg_manager_api = RubyVersionAPI()

    @patch(
        "vulnerabilities.package_managers.RubyVersionAPI.get",
        return_value=VersionResponse(
            valid_versions={"1.0.0", "1.8.0", "2.0.3"}, newer_versions=set()
        ),
    )
    def test_process_file(self, mock_write):
        expected_advisories = [
            Advisory(
                summary="An issue was discovered in rack-protection/lib/rack/protection/path_traversal.rb\nin Sinatra 2.x before 2.0.1 on Windows. Path traversal is possible via backslash\ncharacters.\n",
                vulnerability_id="CVE-2018-7212",
                affected_packages=[
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="gem",
                            namespace=None,
                            name="sinatra",
                            version="1.8.0",
                        ),
                        patched_package=PackageURL(
                            type="gem",
                            namespace=None,
                            name="sinatra",
                            version="2.0.3",
                        ),
                    )
                ],
                references=[
                    Reference(
                        reference_id="",
                        url="https://github.com/sinatra/sinatra/pull/1379",
                        severities=[],
                    )
                ],
            ),
            Advisory(
                summary="Sinatra before 2.0.2 has XSS via the 400 Bad Request page that occurs upon a params parser exception.\n",
                vulnerability_id="CVE-2018-11627",
                affected_packages=[
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="gem",
                            namespace=None,
                            name="sinatra",
                            version="1.0.0",
                        ),
                        patched_package=PackageURL(
                            type="gem",
                            namespace=None,
                            name="sinatra",
                            version="2.0.3",
                        ),
                    ),
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="gem",
                            namespace=None,
                            name="sinatra",
                            version="1.8.0",
                        ),
                        patched_package=PackageURL(
                            type="gem",
                            namespace=None,
                            name="sinatra",
                            version="2.0.3",
                        ),
                    ),
                ],
                references=[
                    Reference(
                        reference_id="",
                        url="https://github.com/sinatra/sinatra/issues/1428",
                        severities=[],
                    )
                ],
            ),
        ]
        found_advisories = []
        for p in MOCK_ADDED_FILES:
            advisory = self.data_src.process_file(p)
            if advisory:
                found_advisories.append(advisory)

        found_advisories = list(map(Advisory.normalized, found_advisories))
        expected_advisories = list(map(Advisory.normalized, expected_advisories))
        assert sorted(found_advisories) == sorted(expected_advisories)

    def test_categorize_versions(self):
        all_versions = ["1.0.0", "1.2.0", "9.0.2", "0.2.3"]
        safe_ver_ranges = ["==1.0.0", ">1.2.0"]

        exp_safe_vers = ["1.0.0", "9.0.2"]
        exp_aff_vers = ["1.2.0", "0.2.3"]

        safe_vers, aff_vers = self.data_src.categorize_versions(all_versions, safe_ver_ranges)
        assert exp_aff_vers == aff_vers
        assert exp_safe_vers == safe_vers
