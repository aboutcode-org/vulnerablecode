# Copyright (c)  nexB Inc. and others. All rights reserved.
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

import os
from unittest import TestCase

from packageurl import PackageURL
from univers.version_specifier import VersionSpecifier

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference
from vulnerabilities.package_managers import GitHubTagsAPI
from vulnerabilities.package_managers import Version
from vulnerabilities.importers.apache_kafka import ApacheKafkaDataSource
from vulnerabilities.importers.apache_kafka import to_version_ranges
from vulnerabilities.helpers import AffectedPackage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "apache_kafka", "cve-list.html")


class TestApacheKafkaDataSource(TestCase):
    def test_to_version_ranges(self):
        # Check single version
        assert [
            VersionSpecifier.from_scheme_version_spec_string("maven", "=3.2.2")
        ] == to_version_ranges("3.2.2")

        # Check range with lower and upper bounds
        assert [
            VersionSpecifier.from_scheme_version_spec_string("maven", ">=3.2.2, <=3.2.3")
        ] == to_version_ranges("3.2.2 to 3.2.3")

        # Check range with "and later"
        assert [
            VersionSpecifier.from_scheme_version_spec_string("maven", ">=3.2.2")
        ] == to_version_ranges("3.2.2 and later")

        # Check combination of above cases
        assert [
            VersionSpecifier.from_scheme_version_spec_string("maven", ">=3.2.2"),
            VersionSpecifier.from_scheme_version_spec_string("maven", ">=3.2.2, <=3.2.3"),
            VersionSpecifier.from_scheme_version_spec_string("maven", "==3.2.2"),
        ] == to_version_ranges("3.2.2 and later, 3.2.2 to 3.2.3, 3.2.2")

    def test_to_advisory(self):
        data_source = ApacheKafkaDataSource(batch_size=1)
        data_source.version_api = GitHubTagsAPI(
            cache={"apache/kafka": [Version("2.1.2"), Version("0.10.2.2")]}
        )
        expected_advisories = [
            Advisory(
                summary="In Apache Kafka versions between 0.11.0.0 and 2.1.0, it is possible to manually\n    craft a Produce request which bypasses transaction/idempotent ACL validation.\n    Only authenticated clients with Write permission on the respective topics are\n    able to exploit this vulnerability. Users should upgrade to 2.1.1 or later\n    where this vulnerability has been fixed.",
                vulnerability_id="CVE-2018-17196",
                affected_packages=[
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="apache",
                            namespace=None,
                            name="kafka",
                            version="0.10.2.2",
                            qualifiers={},
                            subpath=None,
                        ),
                        patched_package=PackageURL(
                            type="apache",
                            namespace=None,
                            name="kafka",
                            version="2.1.2",
                            qualifiers={},
                            subpath=None,
                        ),
                    )
                ],
                references=[
                    Reference(
                        reference_id="", url="https://kafka.apache.org/cve-list", severities=[]
                    ),
                    Reference(
                        reference_id="CVE-2018-17196",
                        url="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17196",
                        severities=[],
                    ),
                ],
            )
        ]
        with open(TEST_DATA) as f:
            found_advisories = data_source.to_advisory(f)

        found_advisories = list(map(Advisory.normalized, found_advisories))
        expected_advisories = list(map(Advisory.normalized, expected_advisories))
        assert sorted(found_advisories) == sorted(expected_advisories)
