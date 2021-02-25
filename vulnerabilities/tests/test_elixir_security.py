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
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import os
from collections import OrderedDict
from unittest import TestCase

from packageurl import PackageURL

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference
from vulnerabilities.importers.elixir_security import ElixirSecurityDataSource
from vulnerabilities.package_managers import HexVersionAPI
from vulnerabilities.tests.utils import advisories_are_equal

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class TestElixirSecurityDataSource(TestCase):
    @classmethod
    def setUpClass(cls):
        data_source_cfg = {
            "repository_url": "https://github.com/dependabot/elixir-security-advisories",
        }
        cls.data_src = ElixirSecurityDataSource(1, config=data_source_cfg)
        cls.data_src.pkg_manager_api = HexVersionAPI(
            {
                "coherence": [
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
            }
        )

    def test_process_file(self):

        path = os.path.join(BASE_DIR, "test_data/elixir_security/test_file.yml")
        expected_advisory = Advisory(
            summary=('The Coherence library has "Mass Assignment"-like vulnerabilities.\n'),
            impacted_package_urls={
                PackageURL(
                    type="hex",
                    name="coherence",
                    version="0.5.1",
                ),
                PackageURL(
                    type="hex",
                    name="coherence",
                    version="0.5.0",
                ),
                PackageURL(
                    type="hex",
                    name="coherence",
                    version="0.4.0",
                ),
                PackageURL(
                    type="hex",
                    name="coherence",
                    version="0.3.1",
                ),
                PackageURL(
                    type="hex",
                    name="coherence",
                    version="0.3.0",
                ),
                PackageURL(
                    type="hex",
                    name="coherence",
                    version="0.2.0",
                ),
                PackageURL(
                    type="hex",
                    name="coherence",
                    version="0.1.3",
                ),
                PackageURL(
                    type="hex",
                    name="coherence",
                    version="0.1.2",
                ),
                PackageURL(
                    type="hex",
                    name="coherence",
                    version="0.1.1",
                ),
                PackageURL(
                    type="hex",
                    name="coherence",
                    version="0.1.0",
                ),
            },
            resolved_package_urls={
                PackageURL(
                    type="hex",
                    name="coherence",
                    version="0.5.2",
                ),
            },
            vuln_references=[
                Reference(
                    reference_id="2aae6e3a-24a3-4d5f-86ff-b964eaf7c6d1",
                ),
                Reference(url="https://github.com/smpallen99/coherence/issues/270"),
            ],
            vulnerability_id="CVE-2018-20301",
        )

        found_advisory = self.data_src.process_file(path)

        assert advisories_are_equal([expected_advisory], [found_advisory])
