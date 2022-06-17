#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import datetime
import os
import shutil
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from unittest import TestCase
from unittest.mock import MagicMock
from unittest.mock import patch

import git
import pytest
from packageurl import PackageURL

from vulnerabilities.importer import GitImporter
from vulnerabilities.importer import InvalidConfigurationError
from vulnerabilities.importer import OvalImporter
from vulnerabilities.importer import _include_file
from vulnerabilities.oval_parser import OvalParser

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/")


def load_oval_data():
    etrees_of_oval = {}
    for f in os.listdir(TEST_DATA):
        if f.endswith("oval_data.xml"):
            path = os.path.join(TEST_DATA, f)
            provider = f.split("_")[0]
            etrees_of_oval[provider] = ET.parse(path)
    return etrees_of_oval


@pytest.fixture
def clone_url(tmp_path):
    git_dir = tmp_path / "git_dir"
    repo = git.Repo.init(str(git_dir))
    new_file_path = str(git_dir / "file")
    open(new_file_path, "wb").close()
    repo.index.add([new_file_path])
    repo.index.commit("Added a new file")
    try:
        yield str(git_dir)
    finally:
        shutil.rmtree(git_dir)


@pytest.fixture
def clone_url2(tmp_path):
    git_dir = tmp_path / "git_dir2"
    repo = git.Repo.init(str(git_dir))
    new_file_path = str(git_dir / "file2")
    open(new_file_path, "wb").close()
    repo.index.add([new_file_path])
    repo.index.commit("Added a new file")

    try:
        yield str(git_dir)
    finally:
        shutil.rmtree(git_dir)


def mk_ds(**kwargs):
    # just for convenience, since this is a mandatory parameter we always pass a value
    if "repository_url" not in kwargs:
        kwargs["repository_url"] = "asdf"

    last_run_date = kwargs.pop("last_run_date", None)
    cutoff_date = kwargs.pop("cutoff_date", None)

    # batch_size is a required parameter of the base class, unrelated to these tests
    return GitImporter(
        batch_size=100, last_run_date=last_run_date, cutoff_date=cutoff_date, config=kwargs
    )


def test_GitImporter_repository_url_required(no_mkdir, no_rmtree):

    with pytest.raises(InvalidConfigurationError):
        GitImporter(batch_size=100)


def test_GitImporter_validate_configuration_create_working_directory_must_be_set_when_working_directory_is_default(
    no_mkdir, no_rmtree
):

    with pytest.raises(InvalidConfigurationError):
        mk_ds(create_working_directory=False)


def test_GitImporter_validate_configuration_remove_working_directory_must_be_set_when_working_directory_is_default(
    no_mkdir, no_rmtree
):

    with pytest.raises(InvalidConfigurationError):
        mk_ds(remove_working_directory=False)


@patch("os.path.exists", return_value=True)
def test_GitImporter_validate_configuration_remove_working_directory_is_applied(
    no_mkdir, no_rmtree
):

    ds = mk_ds(remove_working_directory=False, working_directory="/some/directory")

    assert not ds.config.remove_working_directory


def test_GitImporter_validate_configuration_working_directory_must_exist_when_create_working_directory_is_not_set(
    no_mkdir, no_rmtree
):

    with pytest.raises(InvalidConfigurationError):
        mk_ds(working_directory="/does/not/exist", create_working_directory=False)


def test_GitImporter_contextmgr_working_directory_is_created_and_removed(tmp_path, clone_url):

    wd = tmp_path / "working"
    ds = mk_ds(
        working_directory=str(wd),
        create_working_directory=True,
        remove_working_directory=True,
        repository_url=clone_url,
    )

    with ds:
        assert str(wd) == ds.config.working_directory
        assert (wd / ".git").exists()
        assert (wd / "file").exists()

    assert not (wd / ".git").exists()


@patch("tempfile.mkdtemp")
def test_GitImporter_contextmgr_calls_mkdtemp_if_working_directory_is_not_set(
    mkdtemp, tmp_path, clone_url
):

    mkdtemp.return_value = str(tmp_path / "working")
    ds = mk_ds(repository_url=clone_url)

    with ds:
        assert mkdtemp.called
        assert ds.config.working_directory == str(tmp_path / "working")


def test_GitImporter_contextmgr_uses_existing_repository(
    clone_url,
    clone_url2,
    no_mkdir,
    no_rmtree,
):
    ds = mk_ds(
        working_directory=clone_url,
        repository_url=clone_url2,
        create_working_directory=False,
        remove_working_directory=False,
    )

    with ds:
        # also make sure we switch the branch (original do not have file2)
        assert os.path.exists(os.path.join(ds.config.working_directory, "file2"))

    assert os.path.exists(ds.config.working_directory)


def test__include_file():

    assert _include_file("foo.json", subdir=None, recursive=False, file_ext=None)
    assert not _include_file("foo/bar.json", subdir=None, recursive=False, file_ext=None)
    assert _include_file("foo/bar.json", subdir="foo/", recursive=False, file_ext=None)
    assert _include_file("foo/bar.json", subdir="foo", recursive=False, file_ext=None)
    assert not _include_file("foobar.json", subdir="foo", recursive=False, file_ext=None)
    assert _include_file("foo/bar.json", subdir=None, recursive=True, file_ext=None)
    assert not _include_file("foo/bar.json", subdir=None, recursive=True, file_ext="yaml")
    assert _include_file("foo/bar/baz.json", subdir="foo", recursive=True, file_ext="json")
    assert not _include_file("bar/foo/baz.json", subdir="foo", recursive=True, file_ext="json")


class GitImporterTest(TestCase):

    tempdir = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.tempdir = tempfile.mkdtemp()
        zip_path = os.path.join(TEST_DATA, "advisory-db.zip")

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(cls.tempdir)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tempdir)

    def setUp(self) -> None:
        self.repodir = os.path.join(self.tempdir, "advisory-db")

    def mk_ds(self, **kwargs) -> GitImporter:
        kwargs["working_directory"] = self.repodir
        kwargs["create_working_directory"] = False
        kwargs["remove_working_directory"] = False

        ds = mk_ds(**kwargs)
        ds._update_from_remote = MagicMock()
        return ds

    def test_file_changes_last_run_date_and_cutoff_date_is_None(self):

        ds = self.mk_ds(last_run_date=None, cutoff_date=None)

        with ds:
            added_files, updated_files = ds.file_changes(
                subdir="rust", recursive=True, file_ext="toml"
            )

        assert len(updated_files) == 0

        assert set(added_files) == {
            os.path.join(self.repodir, f)
            for f in {
                "rust/cargo/CVE-2019-16760.toml",
                "rust/rustdoc/CVE-2018-1000622.toml",
                "rust/std/CVE-2018-1000657.toml",
                "rust/std/CVE-2018-1000810.toml",
                "rust/std/CVE-2019-12083.toml",
            }
        }

    def test_file_changes_cutoff_date_is_now(self):

        ds = self.mk_ds(last_run_date=None, cutoff_date=datetime.datetime.now())

        with ds:
            added_files, updated_files = ds.file_changes(
                subdir="cargo", recursive=True, file_ext="toml"
            )

        assert len(added_files) == 0
        assert len(updated_files) == 0

    def test_file_changes_include_new_advisories(self):

        last_run_date = datetime.datetime(year=2020, month=3, day=29)
        cutoff_date = last_run_date - datetime.timedelta(weeks=52 * 3)
        ds = self.mk_ds(last_run_date=last_run_date, cutoff_date=cutoff_date)

        with ds:
            added_files, updated_files = ds.file_changes(
                subdir="crates", recursive=True, file_ext="toml"
            )

        assert len(added_files) >= 2
        assert os.path.join(self.repodir, "crates/bitvec/RUSTSEC-2020-0007.toml") in added_files
        assert os.path.join(self.repodir, "crates/hyper/RUSTSEC-2020-0008.toml") in added_files
        assert len(updated_files) == 0

    def test_file_changes_include_fixed_advisories(self):
        # pick a date that includes commit 9889ed0831b4fb4beb7675de361926d2e9a99c20
        # ("Fix patched version for RUSTSEC-2020-0008")
        last_run_date = datetime.datetime(
            year=2020, month=3, day=31, hour=17, minute=40, tzinfo=datetime.timezone.utc
        )
        ds = self.mk_ds(last_run_date=last_run_date, cutoff_date=None)

        with ds:
            added_files, updated_files = ds.file_changes(
                subdir="crates", recursive=True, file_ext="toml"
            )

        assert len(added_files) == 0
        assert len(updated_files) == 1
        assert os.path.join(self.repodir, "crates/hyper/RUSTSEC-2020-0008.toml") in updated_files


class TestOvalImporter(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.oval_data_src = OvalImporter(1)

    def test_create_purl(self):
        purl1 = PackageURL(name="ffmpeg", type="test", version="1.2.0")

        assert purl1 == self.oval_data_src.create_purl(
            pkg_name="ffmpeg", pkg_version="1.2.0", pkg_data={"type": "test"}
        )

        purl2 = PackageURL(
            name="notepad",
            type="example",
            version="7.9.6",
            namespace="ns",
            qualifiers={"distro": "sample"},
            subpath="root",
        )
        assert purl2 == self.oval_data_src.create_purl(
            pkg_name="notepad",
            pkg_version="7.9.6",
            pkg_data={
                "namespace": "ns",
                "qualifiers": {"distro": "sample"},
                "subpath": "root",
                "type": "example",
            },
        )

    def test__collect_pkgs(self):

        xmls = load_oval_data()

        expected_suse_pkgs = {"cacti-spine", "apache2-mod_perl", "cacti", "apache2-mod_perl-devel"}
        expected_ubuntu_pkgs = {"potrace", "tor"}

        translations = {"less than": "<"}

        found_suse_pkgs = self.oval_data_src._collect_pkgs(
            OvalParser(translations, xmls["suse"]).get_data()
        )

        found_ubuntu_pkgs = self.oval_data_src._collect_pkgs(
            OvalParser(translations, xmls["ubuntu"]).get_data()
        )

        assert found_suse_pkgs == expected_suse_pkgs
        assert found_ubuntu_pkgs == expected_ubuntu_pkgs
