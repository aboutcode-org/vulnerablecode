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
from unittest import TestCase

from packageurl import PackageURL
from univers.version_range import VersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Reference
from vulnerabilities.importers.rust import RustImporter
from vulnerabilities.importers.rust import categorize_versions
from vulnerabilities.importers.rust import get_advisory_data
from vulnerabilities.package_managers import CratesVersionAPI
from vulnerabilities.package_managers import Version
from vulnerabilities.utils import AffectedPackage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/rust")

MOCKED_CRATES_API_VERSIONS = CratesVersionAPI(
    cache={
        "bitvec": {Version("0.10.0"), Version("0.12.0"), Version("0.18.0")},
        "bumpalo": {Version("2.8.0"), Version("3.0.1"), Version("3.2.5")},
        "cbox": {Version("0.10.0"), Version("0.12.0"), Version("0.18.0")},
        "flatbuffers": {Version("0.3.0"), Version("0.5.0"), Version("0.6.5")},
        "hyper": {Version("0.10.0"), Version("0.12.0"), Version("0.13.0")},
        "byte_struct": {Version("0.6.1"), Version("0.6.0"), Version("1.0.0")},
    }
)


def test_categorize_versions():
    flatbuffers_versions = MOCKED_CRATES_API_VERSIONS.get("flatbuffers").valid_versions

    unaffected_ranges = [VersionRange.from_scheme_version_spec_string("semver", "< 0.4.0")]
    affected_ranges = [
        VersionRange.from_scheme_version_spec_string("semver", ">= 0.4.0"),
        VersionRange.from_scheme_version_spec_string("semver", "<= 0.6.0"),
    ]
    resolved_ranges = [VersionRange.from_scheme_version_spec_string("semver", ">= 0.6.1")]

    unaffected_versions, affected_versions = categorize_versions(
        set(flatbuffers_versions),
        unaffected_ranges,
        affected_ranges,
        resolved_ranges,
    )

    assert len(unaffected_versions) == 2
    assert "0.3.0" in unaffected_versions
    assert "0.6.5" in unaffected_versions

    assert len(affected_versions) == 1
    assert "0.5.0" in affected_versions


def test_categorize_versions_without_affected_ranges():
    all_versions = {"1.0", "1.1", "2.0", "2.1", "3.0", "3.1"}

    unaffected_ranges = [VersionRange.from_scheme_version_spec_string("semver", "< 1.2")]
    affected_ranges = []
    resolved_ranges = [VersionRange.from_scheme_version_spec_string("semver", ">= 3.0")]

    unaffected_versions, affected_versions = categorize_versions(
        all_versions,
        unaffected_ranges,
        affected_ranges,
        resolved_ranges,
    )

    assert len(unaffected_versions) == 4
    assert "1.0" in unaffected_versions
    assert "1.1" in unaffected_versions
    assert "3.0" in unaffected_versions
    assert "3.1" in unaffected_versions

    assert len(affected_versions) == 2
    assert "2.0" in affected_versions
    assert "2.1" in affected_versions


def test_categorize_versions_with_only_affected_ranges():
    all_versions = {"1.0", "1.1", "2.0", "2.1", "3.0", "3.1"}

    unaffected_ranges = []
    affected_ranges = [
        VersionRange.from_scheme_version_spec_string("semver", "> 1.2"),
        VersionRange.from_scheme_version_spec_string("semver", "<= 2.1"),
    ]
    resolved_ranges = []

    unaffected_versions, affected_versions = categorize_versions(
        all_versions,
        unaffected_ranges,
        affected_ranges,
        resolved_ranges,
    )

    assert len(unaffected_versions) == 4
    assert "1.0" in unaffected_versions
    assert "1.1" in unaffected_versions
    assert "3.0" in unaffected_versions
    assert "3.1" in unaffected_versions

    assert len(affected_versions) == 2
    assert "2.0" in affected_versions
    assert "2.1" in affected_versions


def test_categorize_versions_without_any_ranges():
    all_versions = {"1.0", "1.1", "2.0", "2.1", "3.0", "3.1"}

    unaffected, affected = categorize_versions(all_versions, [], [], [])

    assert len(unaffected) == 0
    assert len(affected) == 0


class RustImportTest(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        data_source_cfg = {
            "repository_url": "",
        }
        cls.data_src = RustImporter(1, config=data_source_cfg)
        cls.data_src._crates_api = MOCKED_CRATES_API_VERSIONS

    def test_load_advisory(self):
        md_path = os.path.join(TEST_DATA, "RUSTSEC-2021-0032.md")
        data = self.data_src._load_advisory(md_path)
        expected_data = Advisory(
            summary="",
            vulnerability_id="CVE-2021-28033",
            affected_packages=[
                AffectedPackage(
                    vulnerable_package=PackageURL(
                        type="cargo",
                        name="byte_struct",
                        version="0.6.0",
                    ),
                    patched_package=PackageURL(
                        type="cargo",
                        name="byte_struct",
                        version="0.6.1",
                    ),
                )
            ],
            references=[
                Reference(
                    reference_id="",
                    url="https://github.com/wwylele/byte-struct-rs/issues/1",
                    severities=[],
                ),
                Reference(
                    reference_id="RUSTSEC-2021-0032",
                    url="https://rustsec.org/advisories/RUSTSEC-2021-0032.html",
                    severities=[],
                ),
            ],
        )
        assert expected_data == data

    def test_load_toml_from_md(self):
        md_path = os.path.join(TEST_DATA, "CVE-2019-16760.md")
        loaded_data = get_advisory_data(md_path)
        expected_data = {
            "advisory": {
                "aliases": ["GHSA-phjm-8x66-qw4r"],
                "date": "2019-09-30",
                "id": "CVE-2019-16760",
                "package": "cargo",
                "url": "https://groups.google.com/forum/#!topic/rustlang-security-announcements/rVQ5e3TDnpQ",  # nopep8
            },
            "versions": {"patched": [">= 1.26.0"]},
        }

        assert loaded_data == expected_data
