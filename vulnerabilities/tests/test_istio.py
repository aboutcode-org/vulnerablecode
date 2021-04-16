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

import datetime
import os
from collections import OrderedDict
from unittest import TestCase

from packageurl import PackageURL

from vulnerabilities.data_source import Advisory, Reference
from vulnerabilities.importers.istio import IstioDataSource
from vulnerabilities.package_managers import GitHubTagsAPI
from vulnerabilities.helpers import AffectedPackageWithPatchedPackage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class TestIstioDataSource(TestCase):
    @classmethod
    def setUpClass(cls):
        data_source_cfg = {
            "repository_url": "",
        }
        cls.data_src = IstioDataSource(1, config=data_source_cfg)
        cls.data_src.version_api = GitHubTagsAPI(
            {
                "istio/istio": [
                    "1.0.0",
                    "1.1.0",
                    "1.1.1",
                    "1.1.17",
                    "1.2.1",
                    "1.2.7",
                    "1.3.0",
                    "1.3.1",
                    "1.3.2",
                    "1.9.1",
                ]
            }
        )

    def test_get_data_from_md(self):
        path = os.path.join(BASE_DIR, "test_data/istio/test_file.md")
        actual_data = self.data_src.get_data_from_md(path)
        expected_data = {
            "title": "ISTIO-SECURITY-2019-001",
            "subtitle": "Security Bulletin",
            "description": "Incorrect access control.",
            "cves": ["CVE-2019-12243"],
            "cvss": "8.9",
            "vector": "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N/E:H/RL:O/RC:C",
            "releases": ["1.1 to 1.1.15", "1.2 to 1.2.6", "1.3 to 1.3.1"],
            "publishdate": datetime.date(2019, 5, 28),
        }

        assert expected_data == actual_data

    def test_process_file(self):

        path = os.path.join(BASE_DIR, "test_data/istio/test_file.md")
        expected_data = [
            Advisory(
                summary="Incorrect access control.",
                vulnerability_id="CVE-2019-12243",
                affected_packages_with_patched_package=[
                    AffectedPackageWithPatchedPackage(
                        vulnerable_package=PackageURL(
                            type="golang",
                            name="istio",
                            version="1.1.0",
                        ),
                        patched_package=PackageURL(
                            type="golang",
                            name="istio",
                            version="1.1.17",
                        ),
                    ),
                    AffectedPackageWithPatchedPackage(
                        vulnerable_package=PackageURL(
                            type="golang",
                            name="istio",
                            version="1.1.1",
                        ),
                        patched_package=PackageURL(
                            type="golang",
                            name="istio",
                            version="1.1.17",
                        ),
                    ),
                    AffectedPackageWithPatchedPackage(
                        vulnerable_package=PackageURL(
                            type="golang",
                            name="istio",
                            version="1.2.1",
                        ),
                        patched_package=PackageURL(
                            type="golang",
                            name="istio",
                            version="1.2.7",
                        ),
                    ),
                    AffectedPackageWithPatchedPackage(
                        vulnerable_package=PackageURL(
                            type="golang",
                            name="istio",
                            version="1.3.0",
                        ),
                        patched_package=PackageURL(
                            type="golang",
                            name="istio",
                            version="1.3.2",
                        ),
                    ),
                    AffectedPackageWithPatchedPackage(
                        vulnerable_package=PackageURL(
                            type="golang",
                            name="istio",
                            version="1.3.1",
                        ),
                        patched_package=PackageURL(
                            type="golang",
                            name="istio",
                            version="1.3.2",
                        ),
                    ),
                    AffectedPackageWithPatchedPackage(
                        vulnerable_package=PackageURL(
                            type="github",
                            name="istio",
                            version="1.1.0",
                        ),
                        patched_package=PackageURL(
                            type="github",
                            name="istio",
                            version="1.1.17",
                        ),
                    ),
                    AffectedPackageWithPatchedPackage(
                        vulnerable_package=PackageURL(
                            type="github",
                            name="istio",
                            version="1.1.1",
                        ),
                        patched_package=PackageURL(
                            type="github",
                            name="istio",
                            version="1.1.17",
                        ),
                    ),
                    AffectedPackageWithPatchedPackage(
                        vulnerable_package=PackageURL(
                            type="github",
                            name="istio",
                            version="1.2.1",
                        ),
                        patched_package=PackageURL(
                            type="github",
                            name="istio",
                            version="1.2.7",
                        ),
                    ),
                    AffectedPackageWithPatchedPackage(
                        vulnerable_package=PackageURL(
                            type="github",
                            name="istio",
                            version="1.3.0",
                        ),
                        patched_package=PackageURL(
                            type="github",
                            name="istio",
                            version="1.3.2",
                        ),
                    ),
                    AffectedPackageWithPatchedPackage(
                        vulnerable_package=PackageURL(
                            type="github",
                            name="istio",
                            version="1.3.1",
                        ),
                        patched_package=PackageURL(
                            type="github",
                            name="istio",
                            version="1.3.2",
                        ),
                    ),
                ],
                references=[],
            )
        ]

        found_data = self.data_src.process_file(path)
        assert expected_data == found_data
