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
from unittest import TestCase
from unittest.mock import patch, MagicMock

import pygit2
import pytest

from vulnerabilities.data_source import GitDataSource, _include_file
from vulnerabilities.data_source import InvalidConfigurationError

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, 'test_data/')


def mk_ds(**kwargs):
    # just for convenience, since this is a manadory parameter we always pass a value
    if 'repository_url' not in kwargs:
        kwargs['repository_url'] ='asdf'

    last_run_date = kwargs.pop('last_run_date', None)
    cutoff_date = kwargs.pop('cutoff_date', None)

    # batch_size is a required parameter of the base class, unrelated to these tests
    return GitDataSource(batch_size=100, last_run_date=last_run_date, cutoff_date=cutoff_date, config=kwargs)


def test_GitDataSource_repository_url_required(no_mkdir, no_rmtree):

    with pytest.raises(InvalidConfigurationError):
        GitDataSource(batch_size=100)


def test_GitDataSource_validate_configuration_create_working_directory_must_be_set_when_working_directory_is_default(
        no_mkdir, no_rmtree):

    with pytest.raises(InvalidConfigurationError):
        mk_ds(create_working_directory=False)


def test_GitDataSource_validate_configuration_remove_working_directory_must_be_set_when_working_directory_is_default(
        no_mkdir, no_rmtree):

    with pytest.raises(InvalidConfigurationError):
        mk_ds(remove_working_directory=False)


@patch('os.path.exists', return_value=True)
def test_GitDataSource_validate_configuration_remove_working_directory_is_applied(no_mkdir, no_rmtree):

    ds = mk_ds(remove_working_directory=False, working_directory='/some/directory')

    assert not ds.config.remove_working_directory


def test_GitDataSource_validate_configuration_working_directory_must_exist_when_create_working_directory_is_not_set(
        no_mkdir, no_rmtree):

    with pytest.raises(InvalidConfigurationError):
        mk_ds(working_directory='/does/not/exist', create_working_directory=False)


@patch('os.path.exists', return_value=False)
@patch('shutil.rmtree')
@patch('pygit2.clone_repository')
@patch('os.mkdir')
def test_GitDataSource_contextmgr_working_directory_is_created_and_removed(mkdir, clone_repository, rmtree, _):

    wd = '/some/working/directory'
    ds = mk_ds(working_directory=wd, create_working_directory=True, remove_working_directory=True)

    with ds:
        assert wd == ds.config.working_directory
        assert mkdir.called_with(wd)

    assert clone_repository.called_with('asdf', wd, checkout_branch=ds.config.branch)
    assert rmtree.called_with(wd)


@patch('shutil.rmtree')
@patch('pygit2.clone_repository')
@patch('tempfile.mkdtemp', return_value='/fake/tempdir')
def test_GitDataSource_contextmgr_calls_mkdtemp_if_working_directory_is_not_set(mkdtemp, *_):

    ds = mk_ds()

    with ds:
        assert mkdtemp.called
        assert ds.config.working_directory == '/fake/tempdir'


@patch('os.path.exists', return_value=True)
@patch('pygit2.Repository')
@patch('pygit2.clone_repository')
@patch('pygit2.discover_repository', return_value='/fake/tempdir/.git')
def test_GitDataSource_contextmgr_uses_existing_repository(
        discover_repository,
        clone_repository,
        _,
        no_mkdir,
        no_rmtree,
):
    ds = mk_ds(working_directory='/fake/tempdir', create_working_directory=False, remove_working_directory=False)
    
    with ds:
        assert discover_repository.called
        assert not clone_repository.called


@patch('os.path.exists', return_value=True)
@patch('pygit2.discover_repository', return_value='/fake/tempdir/.git')
@patch('pygit2.Repository')
def test_GitDataSource_contextmgr_switches_branch(Repository, discover_repository, exists, no_mkdir, no_rmtree):

    mock_repo, mock_remote, mock_remote_origin, mock_remote_other = MagicMock(), MagicMock(), MagicMock(), MagicMock()
    mock_master, mock_custom, mock_remote_custom = MagicMock(), MagicMock(), MagicMock()

    mock_master.is_checked_out = lambda: True
    mock_custom.is_checked_out = lambda: False
    mock_repo.branches = {'master': mock_master, 'custom': mock_custom, 'origin/custom': mock_remote_custom}

    repository_url = 'https://foo/bar/baz.git'
    mock_remote.url = repository_url
    mock_remote.name = 'origin'
    mock_repo.remotes = [mock_remote]
    Repository.return_value = mock_repo

    ds = mk_ds(
        repository_url=repository_url,
        working_directory='/fake/tempdir',
        create_working_directory=False,
        remove_working_directory=False,
        branch='custom',
    )

    with ds:
        mock_repo.checkout.assert_called_with(mock_custom, strategy=pygit2.GIT_CHECKOUT_FORCE)


@patch('os.path.exists', return_value=True)
@patch('pygit2.discover_repository', return_value='/fake/tempdir/.git')
@patch('pygit2.Repository')
def test_GitDataSource_contextmgr_fetches_from_remote_in_already_cloned_repository(
        Repository,
        discover_repository,
        exists,
        no_mkdir,
        no_rmtree,
):
    mock_repo, mock_remote_origin, mock_remote_other = MagicMock(), MagicMock(), MagicMock()
    mock_branch, mock_remote_branch = MagicMock(), MagicMock()

    repository_url = 'https://foo/bar/baz.git'
    mock_remote_origin.url = repository_url
    mock_remote_origin.name = 'origin'
    mock_remote_other.url = 'https://some/other/url.git'
    mock_repo.remotes = [mock_remote_other, mock_remote_origin]

    mock_remote_branch.target = 'asdf'
    mock_remote_branch.shorthand = 'origin/master'
    mock_repo.head.shorthand = 'master'
    mock_repo.branches = {'master': mock_branch, 'origin/master': mock_remote_branch}

    Repository.return_value = mock_repo

    ds = mk_ds(
        repository_url=repository_url,
        working_directory='/fake/tempdir',
        create_working_directory=False,
        remove_working_directory=False,
    )

    with ds:
        assert mock_remote_origin.fetch.called
        assert not mock_remote_other.fetch.called


@patch('os.path.exists', return_value=True)
@patch('pygit2.discover_repository', return_value='/fake/tempdir/.git')
@patch('pygit2.Repository')
def test_GitDataSource_contextmgr_adds_missing_remote_to_already_cloned_repository(
        Repository,
        discover_repository,
        exists,
        no_mkdir,
        no_rmtree,
):
    mock_repo, mock_remote, mock_branch, mock_remote_branch = MagicMock(), MagicMock(), MagicMock(), MagicMock()

    repository_url = 'https://foo/bar/baz.git'
    mock_remote_branch.target = 'asdf'
    mock_remote_branch.shorthand = 'added_by_vulnerablecode/master'
    mock_repo.head.shorthand = 'master'
    mock_repo.branches = {'master': mock_branch, 'added_by_vulnerablecode/master': mock_remote_branch}

    mock_remote.name = 'added_by_vulnerablecode'
    mock_remote.url = repository_url
    mock_repo.remotes = MagicMock()
    mock_repo.remotes.create.return_value = mock_remote
    Repository.return_value = mock_repo

    ds = mk_ds(
        repository_url=repository_url,
        working_directory='/fake/tempdir',
        create_working_directory=False,
        remove_working_directory=False,
    )

    with ds:
        mock_repo.remotes.create.assert_called_once_with('added_by_vulnerablecode', repository_url)


def test__include_file():

    assert _include_file('foo.json', subdir=None, recursive=False, file_ext=None)
    assert not _include_file('foo/bar.json', subdir=None, recursive=False, file_ext=None)
    assert _include_file('foo/bar.json', subdir='foo/', recursive=False, file_ext=None)
    assert _include_file('foo/bar.json', subdir='foo', recursive=False, file_ext=None)
    assert not _include_file('foobar.json', subdir='foo', recursive=False, file_ext=None)
    assert _include_file('foo/bar.json', subdir=None, recursive=True, file_ext=None)
    assert not _include_file('foo/bar.json', subdir=None, recursive=True, file_ext='yaml')
    assert _include_file('foo/bar/baz.json', subdir='foo', recursive=True, file_ext='json')
    assert not _include_file('bar/foo/baz.json', subdir='foo', recursive=True, file_ext='json')


class GitDataSourceTest(TestCase):

    tempdir = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.tempdir = tempfile.mkdtemp()
        zip_path = os.path.join(TEST_DATA, 'rust-advisory-db.zip')

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(cls.tempdir)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tempdir)

    def setUp(self) -> None:
        self.repodir = os.path.join(self.tempdir, 'advisory-db')

    def mk_ds(self, **kwargs) -> GitDataSource:
        kwargs['working_directory'] = self.repodir
        kwargs['create_working_directory'] = False
        kwargs['remove_working_directory'] = False

        ds = mk_ds(**kwargs)
        ds._update_from_remote = MagicMock()
        return ds

    def test_file_changes_last_run_date_and_cutoff_date_is_None(self):

        ds = self.mk_ds(last_run_date=None, cutoff_date=None)

        with ds:
            added_files, updated_files = ds.file_changes(subdir='rust', recursive=True, file_ext='toml')

        assert len(updated_files) == 0

        assert set(added_files) == {
            'cargo/CVE-2019-16760.toml',
            'rustdoc/CVE-2018-1000622.toml',
            'std/CVE-2018-1000657.toml',
            'std/CVE-2018-1000810.toml',
            'std/CVE-2019-12083.toml',
        }

    def test_file_changes_cutoff_date_is_now(self):

        ds = self.mk_ds(last_run_date=None, cutoff_date=datetime.datetime.now())

        with ds:
            added_files, updated_files = ds.file_changes(subdir='cargo', recursive=True, file_ext='toml')

        assert len(added_files) == 0
        assert len(updated_files) == 0

    def test_file_changes_include_new_advisories(self):

        last_run_date = datetime.datetime(year=2020, month=3, day=29)
        cutoff_date = last_run_date - datetime.timedelta(weeks=52 * 3)
        ds = self.mk_ds(last_run_date=last_run_date, cutoff_date=cutoff_date)

        with ds:
            added_files, updated_files = ds.file_changes(subdir='crates', recursive=True, file_ext='toml')

        assert len(added_files) >= 2
        assert 'crates/bitvec/RUSTSEC-2020-0007.toml' in added_files
        assert 'crates/hyper/RUSTSEC-2020-0008.toml' in added_files
        assert len(updated_files) == 0

    def test_file_changes_include_fixed_advisories(self):
        # pick a date that includes commit 9889ed0831b4fb4beb7675de361926d2e9a99c20
        # ("Fix patched version for RUSTSEC-2020-0008")
        last_run_date = datetime.datetime(year=2020, month=3, day=31, hour=19, tzinfo=datetime.timezone.utc)
        ds = self.mk_ds(last_run_date=last_run_date, cutoff_date=None)

        with ds:
            added_files, updated_files = ds.file_changes(subdir='crates', recursive=True, file_ext='toml')

        assert len(added_files) == 0
        assert len(updated_files) == 1
        assert 'crates/hyper/RUSTSEC-2020-0008.toml' in updated_files
