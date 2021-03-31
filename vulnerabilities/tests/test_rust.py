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
import datetime
import os
import shutil
import tempfile
import zipfile
from unittest.mock import patch


from universal_versions.version_specifier import VersionSpecifier

from django.test import TestCase

from vulnerabilities import models
from vulnerabilities.importers.rust import categorize_versions
from vulnerabilities.import_runner import ImportRunner
from vulnerabilities.package_managers import VersionAPI
from vulnerabilities.importers.rust import get_advisory_data

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/rust")

MOCKED_CRATES_API_VERSIONS = {
    "bitvec": ["0.10.0", "0.12.0", "0.18.0"],
    "bumpalo": ["2.8.0", "3.0.1", "3.2.5"],
    "cbox": ["0.10.0", "0.12.0", "0.18.0"],
    "flatbuffers": ["0.3.0", "0.5.0", "0.6.5"],
    "hyper": ["0.10.0", "0.12.0", "0.13.0"],
}


def test_categorize_versions():
    flatbuffers_versions = MOCKED_CRATES_API_VERSIONS["flatbuffers"]

    unaffected_ranges = [VersionSpecifier.from_scheme_version_spec_string("semver", "< 0.4.0")]
    affected_ranges = [
        VersionSpecifier.from_scheme_version_spec_string("semver", ">= 0.4.0"),
        VersionSpecifier.from_scheme_version_spec_string("semver", "<= 0.6.0"),
    ]
    resolved_ranges = [VersionSpecifier.from_scheme_version_spec_string("semver", ">= 0.6.1")]

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

    unaffected_ranges = [VersionSpecifier.from_scheme_version_spec_string("semver", "< 1.2")]
    affected_ranges = []
    resolved_ranges = [VersionSpecifier.from_scheme_version_spec_string("semver", ">= 3.0")]

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
        VersionSpecifier.from_scheme_version_spec_string("semver", "> 1.2"),
        VersionSpecifier.from_scheme_version_spec_string("semver", "<= 2.1"),
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


@patch("vulnerabilities.importers.RustDataSource._update_from_remote")
class RustImportTest(TestCase):

    tempdir = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.tempdir = tempfile.mkdtemp()
        zip_path = os.path.join(TEST_DATA, "rust-advisory-db.zip")

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(cls.tempdir)

        cls.importer = models.Importer.objects.create(
            name="rust_unittests",
            license="https://creativecommons.org/publicdomain/zero/1.0/",
            last_run=None,
            data_source="RustDataSource",
            data_source_cfg={
                "repository_url": "https://example.com/unit-tests/advisory-db",
                "working_directory": os.path.join(cls.tempdir, "advisory-db"),
                "create_working_directory": False,
                "remove_working_directory": False,
            },
        )

        cls.crates_api_cache = {k: set(v) for k, v in MOCKED_CRATES_API_VERSIONS.items()}

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tempdir)

    def test_import(self, _):
        runner = ImportRunner(self.importer, 5)

        with patch(
            "vulnerabilities.importers.RustDataSource.crates_api",
            new=VersionAPI(cache=self.crates_api_cache),
        ):
            with patch("vulnerabilities.importers.RustDataSource.set_api"):
                runner.run(
                    cutoff_date=datetime.datetime(
                        year=2020, month=3, day=18, tzinfo=datetime.timezone.utc
                    )
                )

        self.assert_for_package("bitvec", "RUSTSEC-2020-0007")
        self.assert_for_package("bumpalo", "RUSTSEC-2020-0006")
        self.assert_for_package("flatbuffers", "RUSTSEC-2019-0028")
        self.assert_for_package("hyper", "RUSTSEC-2020-0008")

        # There is no data for cbox, because the advisory contains neither affected nor patched or
        # unaffected versions.
        assert models.Package.objects.filter(name="cbox").count() == 0

    def test_load_toml_from_md(self, _):
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

    def assert_for_package(self, package, advisory_id):
        qs = models.Package.objects.filter(name=package)
        versions = MOCKED_CRATES_API_VERSIONS[package]
        assert qs.count() == len(versions)
        unaffected_pkg = qs.get(version=versions[0])
        impacted_pkg = qs.get(version=versions[1])
        resolved_pkg = qs.get(version=versions[2])

        qs = models.VulnerabilityReference.objects.filter(reference_id=advisory_id)
        assert qs.count() == 1
        vuln = qs[0].vulnerability

        assert models.PackageRelatedVulnerability.objects.filter(
            package=unaffected_pkg, vulnerability=vuln, is_vulnerable=False
        )

        assert models.PackageRelatedVulnerability.objects.filter(
            package=resolved_pkg, vulnerability=vuln, is_vulnerable=False
        )

        assert models.PackageRelatedVulnerability.objects.filter(
            package=impacted_pkg, vulnerability=vuln, is_vulnerable=True
        )

    importer = None
