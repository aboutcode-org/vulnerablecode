#
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
import unittest
import xml.etree.ElementTree as ET
from collections import OrderedDict

from packageurl import PackageURL

from vulnerabilities.importers.gentoo import GentooDataSource
from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/gentoo/glsa-201709-09.xml")


class TestGentooDataSource(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data_source_cfg = {
            "repository_url": "https://example.git",
        }
        cls.data_src = GentooDataSource(1, config=data_source_cfg)
        cls.xml_doc = ET.parse(TEST_DATA)
        cls.references = []
        for child in cls.xml_doc.getroot():

            if child.tag == "references":
                cls.references.append(child)

            if child.tag == "affected":
                cls.affected = child

    def test_affected_and_safe_purls(self):
        exp_affected = {
            PackageURL(
                type="ebuild",
                namespace="dev-vcs",
                name="subversion",
                version="0.1.1",
                qualifiers=OrderedDict(),
                subpath=None,
            )
        }
        exp_safe = {
            PackageURL(
                type="ebuild",
                namespace="dev-vcs",
                name="subversion",
                version="1.9.7",
                qualifiers=OrderedDict(),
                subpath=None,
            )
        }

        aff, safe = GentooDataSource.affected_and_safe_purls(self.affected)

        assert aff == exp_affected
        assert safe == exp_safe

    def test_cves_from_reference(self):

        exp_cves = {"CVE-2017-9800"}
        found_cves = set()
        for ref in self.references:
            found_cves.update(GentooDataSource.cves_from_reference(ref))

        assert exp_cves == found_cves

    def test_process_file(self):

        expected_advisories = [
            Advisory(
                summary=(
                    "A command injection vulnerability in "
                    "Subversion may allow remote\n    "
                    "attackers to execute arbitrary code.\n  "
                ),
                impacted_package_urls={
                    PackageURL(
                        type="ebuild",
                        namespace="dev-vcs",
                        name="subversion",
                        version="0.1.1",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    )
                },
                resolved_package_urls={
                    PackageURL(
                        type="ebuild",
                        namespace="dev-vcs",
                        name="subversion",
                        version="1.9.7",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    )
                },
                references=[
                    Reference(
                        url="https://security.gentoo.org/glsa/201709-09",
                        reference_id="GLSA-201709-09",
                    )
                ],
                vulnerability_id="CVE-2017-9800",
            )
        ]

        found_advisories = self.data_src.process_file(TEST_DATA)
        found_advisories = list(map(Advisory.normalized, found_advisories))
        expected_advisories = list(map(Advisory.normalized, expected_advisories))
        assert sorted(found_advisories) == sorted(expected_advisories)
