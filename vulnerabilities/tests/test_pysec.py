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
import json
import os
from unittest import TestCase

from packageurl import PackageURL
from univers.version_range import PypiVersionRange
from univers.versions import PypiVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.importers.pysec import fixed_filter
from vulnerabilities.importers.pysec import get_affected_purl
from vulnerabilities.importers.pysec import get_affected_version_range
from vulnerabilities.importers.pysec import get_aliases
from vulnerabilities.importers.pysec import get_fixed_version
from vulnerabilities.importers.pysec import get_published_date
from vulnerabilities.importers.pysec import get_references
from vulnerabilities.importers.pysec import get_severities
from vulnerabilities.importers.pysec import parse_advisory_data
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.severity_systems import ScoringSystem

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/pysec", "pysec_test.json")


class TestPyPIImporter(TestCase):
    def test_to_advisories(self):
        first_aff_range = [
            "0.2.4",
            "0.2.9",
            "0.3.0",
            "1.0.2",
            "1.0.3",
            "1.0.5",
            "1.0.6",
            "1.1.0",
            "1.2.0",
            "1.2.1",
            "1.3.0",
            "1.3.1",
            "1.3.2",
            "1.4.0",
            "1.5.0",
            "1.5.1",
            "1.5.10",
            "1.5.11",
            "1.5.12",
            "1.5.13",
            "1.5.14",
            "1.5.15",
            "1.5.16",
            "1.5.17",
            "1.5.18",
            "1.5.2",
            "1.5.3",
            "1.5.4",
            "1.5.5",
            "1.5.6",
            "1.5.7",
            "1.5.8",
            "1.6.0",
            "1.6.1",
            "1.6.2",
        ]
        second_aff_range = [
            "1.0",
            "1.1",
            "1.2",
            "1.3",
            "1.4",
            "1.5",
            "1.6",
            "1.7.0",
            "1.7.1",
            "1.7.2",
            "1.7.3",
            "1.7.4",
            "1.7.5",
            "1.7.6",
            "1.7.7",
            "1.7.8",
            "2.0.0",
            "2.1.0",
            "2.2.0",
            "2.2.1",
            "2.2.2",
            "2.3.0",
            "2.3.1",
            "2.3.2",
            "2.4.0",
            "2.5.0",
            "2.5.1",
            "2.5.2",
            "2.5.3",
            "2.6.0",
            "2.6.1",
            "2.6.2",
            "2.7.0",
            "2.8.0",
            "2.8.1",
            "2.8.2",
            "2.9.0",
            "3.0.0",
            "3.1.0",
            "3.1.0.rc1",
            "3.1.0rc1",
            "3.1.1",
            "3.1.2",
            "3.2.0",
            "3.3.0",
            "3.3.1",
            "3.3.2",
            "3.3.3",
            "3.4.0",
            "3.4.1",
            "3.4.2",
            "4.0.0",
            "4.1.0",
            "4.1.1",
            "4.2.0",
            "4.2.1",
            "4.3.0",
            "5.0.0",
            "5.1.0",
            "5.2.0",
            "5.3.0",
            "5.4.0",
            "5.4.0.dev0",
            "5.4.1",
            "6.0.0",
            "6.1.0",
            "6.2.0",
            "6.2.1",
            "6.2.2",
            "7.0.0",
            "7.1.0",
            "7.1.1",
            "7.1.2",
            "7.2.0",
            "8.0.0",
            "8.0.1",
            "8.1.0",
            "8.1.1",
            "8.1.2",
            "8.2.0",
            "8.3.0",
            "8.3.1",
            "8.3.2",
            "8.4.0",
        ]
        with open(TEST_DATA) as f:
            mock_response = json.load(f)

        expected_advisories = [
            AdvisoryData(
                aliases=["CVE-2021-40831", "GHSA-j3f7-7rmc-6wqj"],
                summary="Improper certificate management in AWS IoT Device SDK v2",
                affected_packages=[
                    AffectedPackage(
                        package=PackageURL.from_string("pkg:pypi/awsiotsdk"),
                        affected_version_range=PypiVersionRange(first_aff_range),
                        fixed_version=PypiVersion("1.7.0"),
                    ),
                ],
                references=[
                    Reference(
                        url="https://nvd.nist.gov/vuln/detail/CVE-2021-40831",
                        severities=[
                            VulnerabilitySeverity(
                                system=SCORING_SYSTEMS["cvssv3.1_vector"],
                                value="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                            )
                        ],
                    ),
                    Reference(
                        url="https://github.com/aws/aws-iot-device-sdk-cpp-v2",
                        severities=[
                            VulnerabilitySeverity(
                                system=SCORING_SYSTEMS["cvssv3.1_vector"],
                                value="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                            )
                        ],
                    ),
                ],
                date_published=datetime.datetime(2021, 11, 24, 20, 35, 3, 0).replace(
                    tzinfo=datetime.timezone.utc
                ),
            ),
            AdvisoryData(
                aliases=["CVE-2022-22817", "GHSA-8vj2-vxx3-667w", "PYSEC-2022-10"],
                summary="",
                affected_packages=[
                    AffectedPackage(
                        package=PackageURL.from_string("pkg:pypi/pillow"),
                        affected_version_range=PypiVersionRange(second_aff_range),
                        fixed_version=PypiVersion("9.0.0"),
                    )
                ],
                references=[
                    Reference(
                        url="https://pillow.readthedocs.io/en/stable/releasenotes/9.0.0.html#restrict-builtins"
                        "-available-to-imagemath-eval",
                        severities=[
                            VulnerabilitySeverity(
                                system=ScoringSystem(
                                    identifier="generic_textual",
                                    name="Generic textual severity rating",
                                    url="",
                                    notes="Severity for generic scoring systems. Contains generic textual values like High, Low etc",
                                ),
                                value="HIGH",
                            )
                        ],
                    ),
                    Reference(
                        url="https://lists.debian.org/debian-lts-announce/2022/01/msg00018.html",
                        severities=[
                            VulnerabilitySeverity(
                                system=ScoringSystem(
                                    identifier="generic_textual",
                                    name="Generic textual severity rating",
                                    url="",
                                    notes="Severity for generic scoring systems. Contains generic textual values like High, Low etc",
                                ),
                                value="HIGH",
                            )
                        ],
                    ),
                    Reference(
                        url="https://github.com/advisories/GHSA-8vj2-vxx3-667w",
                        severities=[
                            VulnerabilitySeverity(
                                system=ScoringSystem(
                                    identifier="generic_textual",
                                    name="Generic textual severity rating",
                                    url="",
                                    notes="Severity for generic scoring systems. Contains generic textual values like High, Low etc",
                                ),
                                value="HIGH",
                            )
                        ],
                    ),
                ],
                date_published=datetime.datetime(2022, 1, 10, 14, 12, 0, 853348).replace(
                    tzinfo=datetime.timezone.utc
                ),
            ),
        ]
        found_data = []
        for response in mock_response:
            found_data.append(parse_advisory_data(response))

        assert expected_advisories == found_data

    def test_fixed_filter(self):
        assert list(
            fixed_filter({"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.6.0"}]})
        ) == ["1.6.0"]
        assert list(
            fixed_filter(
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "1.0.0"},
                        {"introduced": "0"},
                        {"fixed": "9.0.0"},
                    ],
                }
            )
        ) == ["1.0.0", "9.0.0"]
        assert list(
            fixed_filter(
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "1.5.0"},
                        {"fixed": "1.5.0"},
                        {"introduced": "4.01"},
                        {"fixed": "9.0g0"},
                        {"introduced": "8.0.4"},
                        {"fixed": "10.8"},
                    ],
                }
            )
        ) == ["1.5.0", "9.0g0", "10.8"]

    def test_get_aliases(self):
        assert get_aliases({"id": "GHSA-j3f7-7rmc-6wqj"}) == ["GHSA-j3f7-7rmc-6wqj"]
        assert get_aliases({"aliases": ["CVE-2021-40831"]}) == ["CVE-2021-40831"]
        self.assertCountEqual(
            get_aliases({"aliases": ["CVE-2021-40831"], "id": "GHSA-j3f7-7rmc-6wqj"}),
            [
                "CVE-2021-40831",
                "GHSA-j3f7-7rmc-6wqj",
            ],
        )
        self.assertCountEqual(
            get_aliases(
                {"aliases": ["CVE-2022-22817", "GHSA-8vj2-vxx3-667w"], "id": "GHSA-j3f7-7rmc-6wqj"}
            ),
            ["CVE-2022-22817", "GHSA-8vj2-vxx3-667w", "GHSA-j3f7-7rmc-6wqj"],
        )

    def test_get_published_date(self):
        assert get_published_date(
            {"id": "GHSA-j3f7-7rmc-6wqj", "published": "2022-01-10T14:12:00Z"}
        ) == datetime.datetime(2022, 1, 10, 14, 12, 0, 0).replace(tzinfo=datetime.timezone.utc)
        assert get_published_date(
            {"id": "GHSA-j3f7-7rmc-6wqj", "published": "2022-01-10T14:12:00.44444Z"}
        ) == datetime.datetime(2022, 1, 10, 14, 12, 0, 444440).replace(tzinfo=datetime.timezone.utc)
        assert get_published_date({"id": "GHSA-j3f7-7rmc-6wqj"}) is None

    def test_get_severities(self):
        assert list(
            get_severities(
                {"id": "GHSA-j3f7-7rmc-6wqj", "ecosystem_specific": {"severity": "HIGH"}}
            )
        ) == [VulnerabilitySeverity(system=SCORING_SYSTEMS["generic_textual"], value="HIGH")]
        assert list(get_severities({"id": "PYSEC-2022-10", "ecosystem_specific": {}})) == []
        assert list(
            get_severities({"id": "PYSEC-2022-10", "database_specific": {"severity": "HIGH"}})
        ) == [VulnerabilitySeverity(system=SCORING_SYSTEMS["generic_textual"], value="HIGH")]

        assert list(
            get_severities({"id": "PYSEC-2022-10", "database_specific": {"severity": "MODERATE"}})
        ) == [VulnerabilitySeverity(system=SCORING_SYSTEMS["generic_textual"], value="MODERATE")]
        assert list(get_severities({"id": "PYSEC-2022-10", "database_specific": {}})) == []
        assert list(get_severities({"id": "PYSEC-2022-10"})) == []
        assert list(
            get_severities(
                {
                    "id": "PYSEC-2022-10",
                    "severity": [
                        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"}
                    ],
                }
            )
        ) == [
            VulnerabilitySeverity(
                system=SCORING_SYSTEMS["cvssv3.1_vector"],
                value="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            )
        ]

        assert list(
            get_severities(
                {
                    "id": "PYSEC-2022-10",
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                        },
                        {
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                        },
                    ],
                }
            )
        ) == [
            VulnerabilitySeverity(
                system=SCORING_SYSTEMS["cvssv3.1_vector"],
                value="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            ),
            VulnerabilitySeverity(
                system=SCORING_SYSTEMS["cvssv3.1_vector"],
                value="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            ),
        ]

    def test_get_references(self):
        assert get_references(
            {
                "id": "PYSEC-2022-10",
                "references": [
                    {
                        "type": "FIX",
                        "url": "https://github.com/pikepdf/pikepdf/commit/3f38f73218e5e782fe411ccbb3b44a793c0b343a",
                    }
                ],
            },
            [],
        ) == [
            Reference(
                url="https://github.com/pikepdf/pikepdf/commit/3f38f73218e5e782fe411ccbb3b44a793c0b343a",
                severities=[],
            )
        ]

        assert get_references(
            {
                "id": "GHSA-j3f7-7rmc-6wqj",
                "references": [
                    {
                        "type": "FIX",
                        "url": "https://github.com/pikepdf/pikepdf/commit/3f38f73218e5e782fe411ccbb3b44a793c0b343a",
                    },
                    {
                        "type": "REPORT",
                        "url": "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=15499",
                    },
                ],
            },
            [],
        ) == [
            Reference(
                url="https://github.com/pikepdf/pikepdf/commit/3f38f73218e5e782fe411ccbb3b44a793c0b343a",
                severities=[],
            ),
            Reference(
                url="https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=15499", severities=[]
            ),
        ]

        assert get_references({"id": "PYSEC-2022-10"}, []) == []

    def test_get_affected_purl(self):
        assert get_affected_purl(
            {"package": {"purl": "pkg:npm/aws-iot-device-sdk-v2"}}, "PYSEC-2022-10"
        ) == PackageURL.from_string("pkg:npm/aws-iot-device-sdk-v2")

        assert get_affected_purl(
            {"package": {"name": "aws-iot-device-sdk-v2", "ecosystem": "npm"}},
            "GHSA-j3f7-7rmc-6wqj",
        ) == PackageURL(type="npm", name="aws-iot-device-sdk-v2")

    def test_get_affected_version_range(self):
        aff_version_range = [
            "0.2.4",
            "0.2.9",
            "0.3.0",
            "1.0.2",
            "1.0.3",
            "1.0.5",
            "1.0.6",
            "1.1.0",
            "1.2.0",
            "1.2.1",
            "1.3.0",
            "1.3.1",
            "1.3.2",
            "1.4.0",
            "1.5.0",
            "1.5.1",
            "1.5.10",
            "1.5.11",
            "1.5.12",
            "1.5.13",
            "1.5.14",
            "1.5.15",
            "1.5.16",
            "1.5.17",
            "1.5.18",
            "1.5.2",
            "1.5.3",
            "1.5.4",
            "1.5.5",
            "1.5.6",
            "1.5.7",
            "1.5.8",
            "1.6.0",
            "1.6.1",
            "1.6.2",
        ]
        assert get_affected_version_range(
            {"versions": aff_version_range}, "GHSA-j3f7-7rmc-6wqj"
        ) == (PypiVersionRange(aff_version_range))

    def test_get_fixed_version(self):
        assert get_fixed_version({}, "GHSA-j3f7-7rmc-6wqj") == []
        assert get_fixed_version(
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.7.0"}]},
            "GHSA-j3f7-7rmc-6wqj",
        ) == [PypiVersion("1.7.0")]
        assert get_fixed_version(
            {
                "type": "ECOSYSTEM",
                "events": [
                    {"introduced": "0"},
                    {"fixed": "9.0.0"},
                    {"introduced": "0"},
                    {"fixed": "9.0.1"},
                ],
            },
            "GHSA-j3f7-7rmc-6wqj",
        ) == [PypiVersion("9.0.0"), PypiVersion("9.0.1")]
