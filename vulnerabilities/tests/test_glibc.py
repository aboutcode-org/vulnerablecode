#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import os
from datetime import datetime
from textwrap import dedent
from unittest import TestCase

from packageurl import PackageURL
from univers.version_range import VersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importers.glibc import parse_advisory_data

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/glibc")


class TestGlibcImporter(TestCase):
    def test_parse_advisory_data_1(self):
        test_data = parse_advisory_data(
            dedent(
                """syslog: Heap buffer overflow in __vsyslog_internal
            
            __vsyslog_internal did not handle a case where printing a SYSLOG_HEADER
            containing a long program name failed to update the required buffer
            size, leading to the allocation and overflow of a too-small buffer on
            the heap.
            
            CVE-Id: CVE-2023-6246
            Public-Date: 2024-01-30
            Vulnerable-Commit: 52a5be0df411ef3ff45c10c7c308cb92993d15b1 (2.37)
            Fix-Commit: 6bd0e4efcc78f3c0115e5ea9739a1642807450da (2.39)
            Fix-Commit: d1a83b6767f68b3cb5b4b4ea2617254acd040c82 (2.36-126)
            Fix-Commit: 23514c72b780f3da097ecf33a793b7ba9c2070d2 (2.38-42)
            Fix-Commit: 97a4292aa4a2642e251472b878d0ec4c46a0e59a (2.37-57)
            Vulnerable-Commit: b0e7888d1fa2dbd2d9e1645ec8c796abf78880b9 (2.36-16)
            """
            ),
            "GLIBC-SA-2023-0001",
        )

        expected_output = AdvisoryData(
            **{
                "aliases": ["CVE-2023-6246"],
                "affected_packages": [
                    AffectedPackage(
                        package=PackageURL(type="gnu", name="glibc"),
                        affected_version_range=VersionRange.from_string(
                            f'vers:gnu/>={str(SemverVersion(string="2.36.16"))}|<={SemverVersion(string="2.37")}'
                        ),
                        fixed_version=SemverVersion(string="2.36.126"),
                    )
                ],
                "date_published": datetime(2024, 1, 30, 0, 0),
                "summary": "__vsyslog_internal did not handle a case where printing a SYSLOG_HEADER containing a long program name failed to update the required buffer size, leading to the allocation and overflow of a too-small buffer on the heap.",
                "references": [
                    Reference(
                        reference_id="",
                        url="https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2023-0001",
                        severities=[],
                    )
                ],
                "url": "https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2023-0001",
            }
        )

        assert expected_output == test_data
