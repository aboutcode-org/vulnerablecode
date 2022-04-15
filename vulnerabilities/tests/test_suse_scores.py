# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an 'AS IS' BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import os
from unittest import TestCase

from vulnerabilities import severity_systems
from vulnerabilities.helpers import load_yaml
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.importers.suse_scores import SUSESeverityScoreImporter

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
