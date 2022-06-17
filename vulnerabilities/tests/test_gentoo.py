#
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import os
import unittest
import xml.etree.ElementTree as ET
from collections import OrderedDict

from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Reference
from vulnerabilities.importers.gentoo import GentooImporter
from vulnerabilities.utils import AffectedPackage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/gentoo/glsa-201709-09.xml")


class TestGentooImporter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data_source_cfg = {
            "repository_url": "https://example.git",
        }
        cls.data_src = GentooImporter(1, config=data_source_cfg)
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

        aff, safe = GentooImporter.affected_and_safe_purls(self.affected)

        assert aff == exp_affected
        assert safe == exp_safe

    def test_cves_from_reference(self):

        exp_cves = {"CVE-2017-9800"}
        found_cves = set()
        for ref in self.references:
            found_cves.update(GentooImporter.cves_from_reference(ref))

        assert exp_cves == found_cves

    def test_process_file(self):

        expected_advisories = [
            Advisory(
                summary=(
                    "A command injection vulnerability in "
                    "Subversion may allow remote\n    "
                    "attackers to execute arbitrary code.\n  "
                ),
                affected_packages=[
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="ebuild",
                            namespace="dev-vcs",
                            name="subversion",
                            version="0.1.1",
                        ),
                        patched_package=PackageURL(
                            type="ebuild",
                            namespace="dev-vcs",
                            name="subversion",
                            version="1.9.7",
                        ),
                    )
                ],
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
