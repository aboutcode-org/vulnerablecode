#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os
from unittest import TestCase
from unittest.mock import patch

from packageurl import PackageURL

from vulnerabilities.importers import rockylinux
from vulnerabilities.importers.rockylinux import get_cwes_from_rockylinux_advisory
from vulnerabilities.importers.rockylinux import to_advisory
from vulnerabilities.rpm_utils import rpm_to_purl
from vulnerabilities.utils import load_json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "rockylinux")


class TestRockyLinuxImporter(TestCase):
    def test_to_advisory1(self):
        test1 = os.path.join(TEST_DATA, "rockylinux_test1.json")
        mock_response = load_json(test1)
        expected_result = load_json(os.path.join(TEST_DATA, "rockylinux_expected1.json"))
        assert to_advisory(mock_response).to_dict() == expected_result

    def test_to_advisory2(self):
        test2 = os.path.join(TEST_DATA, "rockylinux_test2.json")
        mock_response2 = load_json(test2)
        expected_result2 = load_json(os.path.join(TEST_DATA, "rockylinux_expected2.json"))
        assert to_advisory(mock_response2).to_dict() == expected_result2

    def test_rpm_to_purl(self):
        assert rockylinux.rpm_to_purl("foobar", "rocky-linux") is None
        assert rockylinux.rpm_to_purl("foo-bar-devel-0:sys76", "rocky-linux") is None
        assert rockylinux.rpm_to_purl("cockpit-0:264.1-1.el8.aarch64", "rocky-linux") == PackageURL(
            type="rpm",
            namespace="rocky-linux",
            name="cockpit",
            version="264.1-1.el8",
            qualifiers={"arch": "aarch64"},
        )

    def test_get_cwes_from_rockylinux_advisory(self):
        advisory_data = {
            "cves": [
                {
                    "name": "CVE-2022-3140",
                    "sourceBy": "MITRE",
                    "sourceLink": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3140",
                    "cvss3ScoringVector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L",
                    "cvss3BaseScore": "5.3",
                    "cwe": "CWE-88->CWE-20",
                }
            ]
        }
        assert get_cwes_from_rockylinux_advisory(advisory_data=advisory_data) == [88, 20]
