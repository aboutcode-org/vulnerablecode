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
from vulnerabilities.importers.osv import fixed_filter
from vulnerabilities.importers.osv import get_affected_purl
from vulnerabilities.importers.osv import get_affected_version_range
from vulnerabilities.importers.osv import get_fixed_version
from vulnerabilities.importers.osv import get_published_date
from vulnerabilities.importers.osv import get_references
from vulnerabilities.importers.osv import get_severities
from vulnerabilities.severity_systems import SCORING_SYSTEMS


class TestOSVImporter(TestCase):
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
            {"versions": aff_version_range}, "GHSA-j3f7-7rmc-6wqj", "pypi"
        ) == (
            PypiVersionRange(
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
        )

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
