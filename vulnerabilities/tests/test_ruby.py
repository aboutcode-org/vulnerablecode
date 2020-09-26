# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import os
import pathlib
from unittest.mock import patch
from unittest import TestCase
from collections import OrderedDict

from packageurl import PackageURL

from vulnerabilities.importers.ruby import RubyDataSource
from vulnerabilities.data_source import GitDataSourceConfiguration
from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference
from vulnerabilities.package_managers import RubyVersionAPI


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "ruby")

MOCK_ADDED_FILES = []

for filepath in pathlib.Path(TEST_DATA).glob("**/*.yml"):
    MOCK_ADDED_FILES.append(filepath.absolute())


class RubyDataSourceTest(TestCase):
    @classmethod
    def setUpClass(cls):
        data_source_cfg = {
            "repository_url": "https://github.com/rubysec/ruby-advisory-db.git",
        }
        cls.data_src = RubyDataSource(1, config=data_source_cfg)
        cls.data_src.pkg_manager_api = RubyVersionAPI()

    @patch('vulnerabilities.package_managers.RubyVersionAPI.get',
           return_value={'1.0.0', '1.8.0', '2.0.3'})
    def test_process_file(self, mock_write):
        expected_advisories = {
            Advisory(
                summary=(
                    "An issue was discovered in"
                    " rack-protection/lib/rack/protection/path_traversal.rb\n"
                    "in Sinatra 2.x before 2.0.1 on Windows."
                    " Path traversal is possible via backslash\ncharacters.\n"
                ),
                impacted_package_urls={
                    PackageURL(
                        type="gem",
                        namespace=None,
                        name="sinatra",
                        version="1.8.0",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    )
                },
                resolved_package_urls={
                    PackageURL(
                        type="gem",
                        namespace=None,
                        name="sinatra",
                        version="1.0.0",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    ),
                    PackageURL(
                        type="gem",
                        namespace=None,
                        name="sinatra",
                        version="2.0.3",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    ),
                },
                vuln_references=[
                    Reference(url="https://github.com/sinatra/sinatra/pull/1379")
                ],
                identifier="CVE-2018-7212",
            ),
            Advisory(
                summary=(
                    "Sinatra before 2.0.2 has XSS via the 400 Bad Request "
                    "page that occurs upon a params parser exception.\n"
                ),
                impacted_package_urls={
                    PackageURL(
                        type="gem",
                        namespace=None,
                        name="sinatra",
                        version="1.0.0",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    ),
                    PackageURL(
                        type="gem",
                        namespace=None,
                        name="sinatra",
                        version="1.8.0",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    ),
                },
                resolved_package_urls={
                    PackageURL(
                        type="gem",
                        namespace=None,
                        name="sinatra",
                        version="2.0.3",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    )
                },
                vuln_references=[
                    Reference(url="https://github.com/sinatra/sinatra/issues/1428")
                ],
                identifier="CVE-2018-11627",
            ),
            None,
        }

        found_advisories = set()

        for p in MOCK_ADDED_FILES:
            found_advisories.add(self.data_src.process_file(p))
        assert found_advisories == expected_advisories

    def test_categorize_versions(self):

        all_versions = {"1.0.0", "1.2.0", "9.0.2", "0.2.3"}
        safe_ver_ranges = ["==1.0.0", ">1.2.0"]

        exp_safe_vers = {"1.0.0", "9.0.2"}
        exp_aff_vers = {"1.2.0", "0.2.3"}

        safe_vers, aff_vers = self.data_src.categorize_versions(all_versions, safe_ver_ranges)
        assert exp_aff_vers == aff_vers
        assert exp_safe_vers == safe_vers
