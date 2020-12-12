# Copyright (c) nexB Inc. and others. All rights reserved.
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
from unittest import TestCase
from unittest.mock import patch
from collections import OrderedDict

from vulnerabilities.data_source import Reference
from packageurl import PackageURL

from vulnerabilities.data_source import Advisory
from vulnerabilities.importers.elixir_security import ElixirSecurityDataSource
from vulnerabilities.package_managers import HexVersionAPI


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class TestElixirSecurityDataSource(TestCase):
    @classmethod
    def setUpClass(cls):
        data_source_cfg = {
            "repository_url": 'https://github.com/dependabot/elixir-security-advisories',
        }
        cls.data_src = ElixirSecurityDataSource(1, config=data_source_cfg)
        cls.data_src.pkg_manager_api = HexVersionAPI()

    @patch('vulnerabilities.package_managers.HexVersionAPI.get',
           return_value=[
            "0.5.2",
            "0.5.1",
            "0.5.0",
            "0.4.0",
            "0.3.1",
            "0.3.0",
            "0.2.0",
            "0.1.3",
            "0.1.2",
            "0.1.1",
            "0.1.0",
                    ])
    def test_generate_all_version_list(self, mock_write):
        package = "coherence"
        actual_list = self.data_src.generate_all_version_list(package)
        expected_list = [
            "0.5.2",
            "0.5.1",
            "0.5.0",
            "0.4.0",
            "0.3.1",
            "0.3.0",
            "0.2.0",
            "0.1.3",
            "0.1.2",
            "0.1.1",
            "0.1.0",
        ]
        assert actual_list == expected_list

    @patch('vulnerabilities.package_managers.HexVersionAPI.get',
           return_value=[
            "0.5.2",
            "0.5.1",
            "0.5.0",
            "0.4.0",
            "0.3.1",
            "0.3.0",
            "0.2.0",
            "0.1.3",
            "0.1.2",
            "0.1.1",
            "0.1.0",
                ])
    def test_process_file(self, mock_write):

        path = os.path.join(BASE_DIR, "test_data/elixir_security/test_file.yml")
        expected_data = Advisory(
            summary=(
                'The Coherence library has "Mass Assignment"-like vulnerabilities.\n'
            ),
            impacted_package_urls=[],
            resolved_package_urls={
                PackageURL(
                    type="hex",
                    name="coherence",
                    version="0.5.2",
                ),
            },
            vuln_references=[
                Reference(reference_id='2aae6e3a-24a3-4d5f-86ff-b964eaf7c6d1',
                          url="https://github.com/smpallen99/coherence/issues/270")
            ],
            cve_id="CVE-2018-20301",
        )

        found_data = self.data_src.process_file(path)

        assert expected_data == found_data
