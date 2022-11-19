#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import datetime
from unittest import TestCase

from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import PypiVersionRange
from univers.versions import PypiVersion

from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.importers.osv import extract_fixed_versions as fixed_filter
from vulnerabilities.importers.osv import get_affected_purl
from vulnerabilities.importers.osv import get_affected_version_range
from vulnerabilities.importers.osv import get_fixed_versions
from vulnerabilities.importers.osv import get_published_date
from vulnerabilities.importers.osv import get_references
from vulnerabilities.importers.osv import get_severities
from vulnerabilities.severity_systems import SCORING_SYSTEMS


class TestOSVImporter(TestCase):
    def test_fixed_filter1(self):
        results = list(
            fixed_filter(
                fixed_range={"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.6.0"}]}
            )
        )
        assert results == ["1.6.0"]

    def test_fixed_filter2(self):
        results = list(
            fixed_filter(
                fixed_range={
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "1.0.0"},
                        {"introduced": "0"},
                        {"fixed": "9.0.0"},
                    ],
                }
            )
        )
        assert results == ["1.0.0", "9.0.0"]

    def test_fixed_filter3(self):
        results = list(
            fixed_filter(
                fixed_range={
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
        )
        assert results == ["1.5.0", "9.0g0", "10.8"]

    def test_get_published_date1(self):
        results = get_published_date(
            raw_data={"id": "GHSA-j3f7-7rmc-6wqj", "published": "2022-01-10T14:12:00Z"}
        )
        expected = datetime.datetime(2022, 1, 10, 14, 12, 0, 0).replace(
            tzinfo=datetime.timezone.utc
        )
        assert results == expected

    def test_get_published_date2(self):
        expected = datetime.datetime(2022, 1, 10, 14, 12, 0, 444440).replace(
            tzinfo=datetime.timezone.utc
        )
        results = get_published_date(
            raw_data={"id": "GHSA-j3f7-7rmc-6wqj", "published": "2022-01-10T14:12:00.44444Z"}
        )
        assert results == expected

    def test_get_published_date3(self):
        assert get_published_date(raw_data={"id": "GHSA-j3f7-7rmc-6wqj"}) is None

    def test_get_severities1(self):
        expected = [VulnerabilitySeverity(system=SCORING_SYSTEMS["generic_textual"], value="HIGH")]
        results = list(
            get_severities(
                raw_data={"id": "GHSA-j3f7-7rmc-6wqj", "ecosystem_specific": {"severity": "HIGH"}}
            )
        )
        assert results == expected

    def test_get_severities2(self):
        results = list(
            get_severities(
                raw_data={"id": "PYSEC-2022-10", "ecosystem_specific": {}},
            )
        )
        assert results == []

    def test_get_severities3(self):
        results = list(
            get_severities(
                raw_data={
                    "id": "PYSEC-2022-10",
                    "database_specific": {"severity": "HIGH"},
                }
            )
        )
        expected = [
            VulnerabilitySeverity(system=SCORING_SYSTEMS["generic_textual"], value="HIGH"),
        ]
        assert results == expected

    def test_get_severities4(self):
        expected = [
            VulnerabilitySeverity(system=SCORING_SYSTEMS["generic_textual"], value="MODERATE"),
        ]
        results = list(
            get_severities(
                raw_data={
                    "id": "PYSEC-2022-10",
                    "database_specific": {"severity": "MODERATE"},
                }
            )
        )
        assert results == expected

    def test_get_severities5(self):
        results = list(get_severities(raw_data={"id": "PYSEC-2022-10", "database_specific": {}}))
        assert results == []

    def test_get_severities6(self):
        results = list(get_severities(raw_data={"id": "PYSEC-2022-10"}))
        assert results == []

    def test_get_severities7(self):
        results = list(
            get_severities(
                raw_data={
                    "id": "PYSEC-2022-10",
                    "severity": [
                        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"}
                    ],
                }
            )
        )

        expected = [
            VulnerabilitySeverity(
                system=SCORING_SYSTEMS["cvssv3.1"],
                value="7.1",
                scoring_elements="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            )
        ]
        assert results == expected

    def test_get_severities8(self):
        results = list(
            get_severities(
                raw_data={
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
        )

        expected = [
            VulnerabilitySeverity(
                system=SCORING_SYSTEMS["cvssv3.1"],
                value="7.1",
                scoring_elements="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            ),
            VulnerabilitySeverity(
                system=SCORING_SYSTEMS["cvssv3.1"],
                value="7.1",
                scoring_elements="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            ),
        ]
        assert results == expected

    def test_get_references1(self):
        expected = [
            Reference(
                url="https://github.com/pikepdf/pikepdf/commit/3f38f73218e5e782fe411ccbb3b44a793c0b343a",
                severities=[],
            )
        ]
        results = get_references(
            raw_data={
                "id": "PYSEC-2022-10",
                "references": [
                    {
                        "type": "FIX",
                        "url": "https://github.com/pikepdf/pikepdf/commit/3f38f73218e5e782fe411ccbb3b44a793c0b343a",
                    }
                ],
            },
            severities=[],
        )

        assert results == expected

    def test_get_references2(self):
        expected = [
            Reference(
                url="https://github.com/pikepdf/pikepdf/commit/3f38f73218e5e782fe411ccbb3b44a793c0b343a",
                severities=[],
            ),
            Reference(
                url="https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=15499", severities=[]
            ),
        ]

        results = get_references(
            raw_data={
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
            severities=[],
        )

        assert results == expected

    def test_get_references3(self):
        assert get_references(raw_data={"id": "PYSEC-2022-10"}, severities=[]) == []

    def test_get_affected_purl1(self):
        results = get_affected_purl(
            affected_pkg={"package": {"purl": "pkg:npm/aws-iot-device-sdk-v2"}},
            raw_id="PYSEC-2022-10",
        )
        assert results == PackageURL.from_string("pkg:npm/aws-iot-device-sdk-v2")

    def test_get_affected_purl2(self):
        results = get_affected_purl(
            affected_pkg={"package": {"name": "aws-iot-device-sdk-v2", "ecosystem": "npm"}},
            raw_id="GHSA-j3f7-7rmc-6wqj",
        )
        assert results == PackageURL(type="npm", name="aws-iot-device-sdk-v2")

    def test_get_affected_version_range(self):
        affected_version_range = [
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

        results = get_affected_version_range(
            affected_pkg={"versions": affected_version_range},
            raw_id="GHSA-j3f7-7rmc-6wqj",
            supported_ecosystem="pypi",
        )

        expected = PypiVersionRange(
            constraints=[
                VersionConstraint(comparator="=", version=PypiVersion(string="0.2.4")),
                VersionConstraint(comparator="=", version=PypiVersion(string="0.2.9")),
                VersionConstraint(comparator="=", version=PypiVersion(string="0.3.0")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.0.2")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.0.3")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.0.5")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.0.6")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.1.0")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.2.0")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.2.1")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.3.0")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.3.1")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.3.2")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.4.0")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.5.0")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.5.1")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.5.2")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.5.3")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.5.4")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.5.5")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.5.6")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.5.7")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.5.8")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.5.10")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.5.11")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.5.12")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.5.13")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.5.14")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.5.15")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.5.16")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.5.17")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.5.18")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.6.0")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.6.1")),
                VersionConstraint(comparator="=", version=PypiVersion(string="1.6.2")),
            ]
        )
        assert results == expected

    def test_get_fixed_versions1(self):
        assert get_fixed_versions(fixed_range={}, raw_id="GHSA-j3f7-7rmc-6wqj") == []

    def test_get_fixed_versions2(self):
        results = get_fixed_versions(
            fixed_range={"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.7.0"}]},
            raw_id="GHSA-j3f7-7rmc-6wqj",
        )
        assert results == [PypiVersion("1.7.0")]

    def test_get_fixed_versions3(self):
        results = get_fixed_versions(
            fixed_range={
                "type": "ECOSYSTEM",
                "events": [
                    {"introduced": "0"},
                    {"fixed": "9.0.0"},
                    {"introduced": "0"},
                    {"fixed": "9.0.1"},
                ],
            },
            raw_id="GHSA-j3f7-7rmc-6wqj",
        )

        assert results == [PypiVersion("9.0.0"), PypiVersion("9.0.1")]
