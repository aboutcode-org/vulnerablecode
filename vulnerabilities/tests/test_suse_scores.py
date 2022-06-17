#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
from unittest import TestCase

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.importers.suse_scores import SUSESeverityScoreImporter
from vulnerabilities.utils import load_yaml

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/suse_scores", "suse-cvss-scores.yaml")


class TestSUSESeverityScoreImporter(TestCase):
    def test_to_advisory(self):
        raw_data = load_yaml(TEST_DATA)
        expected_data = [
            AdvisoryData(
                summary="",
                references=[
                    Reference(
                        reference_id="",
                        url="https://ftp.suse.com/pub/projects/security/yaml/suse-cvss-scores.yaml",
                        severities=[
                            VulnerabilitySeverity(
                                system=severity_systems.CVSSV2,
                                value="4.3",
                            ),
                            VulnerabilitySeverity(
                                system=severity_systems.CVSSV2_VECTOR,
                                value="AV:N/AC:M/Au:N/C:N/I:N/A:P",
                            ),
                            VulnerabilitySeverity(
                                system=severity_systems.CVSSV31,
                                value="3.7",
                            ),
                            VulnerabilitySeverity(
                                system=severity_systems.CVSSV31_VECTOR,
                                value="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
                            ),
                        ],
                    )
                ],
                vulnerability_id="CVE-2004-0230",
            ),
            AdvisoryData(
                summary="",
                references=[
                    Reference(
                        reference_id="",
                        url="https://ftp.suse.com/pub/projects/security/yaml/suse-cvss-scores.yaml",
                        severities=[
                            VulnerabilitySeverity(
                                system=severity_systems.CVSSV3,
                                value="8.6",
                            ),
                            VulnerabilitySeverity(
                                system=severity_systems.CVSSV3_VECTOR,
                                value="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                            ),
                        ],
                    )
                ],
                vulnerability_id="CVE-2003-1605",
            ),
        ]

        found_data = SUSESeverityScoreImporter.to_advisory(raw_data)
        found_advisories = list(map(AdvisoryData.normalized, found_data))
        expected_advisories = list(map(AdvisoryData.normalized, expected_data))
        assert sorted(found_advisories) == sorted(expected_advisories)
