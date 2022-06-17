#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
from collections import OrderedDict
from unittest import TestCase

from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Reference
from vulnerabilities.importers.istio import IstioImporter
from vulnerabilities.package_managers import GitHubTagsAPI
from vulnerabilities.package_managers import Version
from vulnerabilities.utils import AffectedPackage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class TestIstioImporter(TestCase):
    @classmethod
    def setUpClass(cls):
        data_source_cfg = {
            "repository_url": "",
        }
        cls.data_src = IstioImporter(1, config=data_source_cfg)
        cls.data_src.version_api = GitHubTagsAPI(
            {
                "istio/istio": [
                    Version(value="1.0.0"),
                    Version(value="1.1.0"),
                    Version(value="1.1.1"),
                    Version(value="1.1.17"),
                    Version(value="1.2.1"),
                    Version(value="1.2.7"),
                    Version(value="1.3.0"),
                    Version(value="1.3.1"),
                    Version(value="1.3.2"),
                    Version(value="1.9.1"),
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
            "publishdate": "2019-05-28",
        }

        assert expected_data == actual_data

    def test_process_file(self):

        path = os.path.join(BASE_DIR, "test_data/istio/test_file.md")
        expected_data = [
            Advisory(
                summary="Incorrect access control.",
                vulnerability_id="CVE-2019-12243",
                affected_packages=[
                    AffectedPackage(
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
                    AffectedPackage(
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
                    AffectedPackage(
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
                    AffectedPackage(
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
                    AffectedPackage(
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
                    AffectedPackage(
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
                    AffectedPackage(
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
                    AffectedPackage(
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
                    AffectedPackage(
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
                    AffectedPackage(
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
                references=[
                    Reference(
                        reference_id="ISTIO-SECURITY-2019-001",
                        url="https://istio.io/latest/news/security/ISTIO-SECURITY-2019-001/",
                    )
                ],
            )
        ]

        found_data = self.data_src.process_file(path)
        assert expected_data == found_data
