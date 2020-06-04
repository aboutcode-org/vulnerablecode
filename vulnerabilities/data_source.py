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

import dataclasses
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any
from typing import ContextManager
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional
from typing import Sequence
from typing import Set
from typing import Tuple

import pygit2
from packageurl import PackageURL


@dataclasses.dataclass
class Advisory:
    """
    This data class expresses the contract between data sources and the import runner.
    Data sources are expected to be usable as context managers and generators, yielding batches of
    Advisory sequences.

    NB: There are two representations for package URLs that are commonly used by code consuming this
        data class; PackageURL objects and strings. As a convention, the former is referred to in
        variable names, etc. as "package_urls" and the latter as "purls".
    """
    summary: str
    impacted_package_urls: Iterable[PackageURL]
    resolved_package_urls: Iterable[PackageURL] = dataclasses.field(default_factory=list)
    reference_urls: Sequence[str] = dataclasses.field(default_factory=list)
    reference_ids: Sequence[str] = dataclasses.field(default_factory=list)
    cve_id: Optional[str] = None

    def __hash__(self):
        s = '{}{}{}{}{}'.format(
            self.summary,
            ''.join(sorted([str(p) for p in self.impacted_package_urls])),
            ''.join(sorted([str(p) for p in self.resolved_package_urls])),
            ''.join(sorted(self.reference_urls)),
            self.cve_id,
        )
        return hash(s)


class InvalidConfigurationError(Exception):
    pass


@dataclasses.dataclass
class DataSourceConfiguration:
    batch_size: int


class DataSource(ContextManager):
    """
    This class defines how importers consume advisories from a data source.

    It makes a distinction between newly added records since the last run and modified records. This
    allows the import logic to pick appropriate database operations.
    """

    CONFIG_CLASS = DataSourceConfiguration

    def __init__(
            self,
            batch_size: int,
            last_run_date: Optional[datetime] = None,
            cutoff_date: Optional[datetime] = None,
            config: Optional[Mapping[str, Any]] = None,
    ):
        """
        Create a DataSource instance.

        :param batch_size: Maximum number of records to return from added_advisories() and
               updated_advisories()
        :param last_run_date: Optional timestamp when this data source was last inspected
        :param cutoff_date: Optional timestamp, records older than this will be ignored
        :param config: Optional dictionary with subclass-specific configuration
        """
        config = config or {}
        try:
            self.config = self.__class__.CONFIG_CLASS(batch_size, **config)
            # These really should be declared in DataSourceConfiguration above but that would
            # prevent DataSource subclasses from declaring mandatory parameters (i.e. positional
            # arguments)
            setattr(self.config, 'last_run_date', last_run_date)
            setattr(self.config, 'cutoff_date', cutoff_date)
        except Exception as e:
            raise InvalidConfigurationError(str(e))

        self.validate_configuration()

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    @property
    def cutoff_timestamp(self) -> int:
        """
        :return: An integer Unix timestamp of the last time this data source was queried or the
        cutoff date passed in the constructor, whichever is more recent.
        """
        if not hasattr(self, '_cutoff_timestamp'):
            last_run = 0
            if self.config.last_run_date is not None:
                last_run = int(self.config.last_run_date.timestamp())

            cutoff = 0
            if self.config.cutoff_date is not None:
                cutoff = int(self.config.cutoff_date.timestamp())

            setattr(self, '_cutoff_timestamp', max(last_run, cutoff))

        return self._cutoff_timestamp

    def validate_configuration(self) -> None:
        """
        Subclasses can perform more complex validation than what is handled by data classes and
        their type annotations.

        This method is called in the constructor. It should raise InvalidConfigurationError with a
        human-readable message.
        """
        pass

    def added_advisories(self) -> Set[Advisory]:
        """
        Subclasses yield batch_size sized batches of Advisory objects that have been added to the
        data source since the last run or self.cutoff_date.
        """
        return set()

    def updated_advisories(self) -> Set[Advisory]:
        """
        Subclasses yield batch_size sized batches of Advisory objects that have been modified since
        the last run or self.cutoff_date.

        NOTE: Data sources that do not enable detection of changes to existing records vs added
              records must only implement this method, not added_advisories(). The ImportRunner
              relies on this contract to decide between insert and update operations.
        """
        return set()

    def error(self, msg: str) -> None:
        """
        Helper method for raising InvalidConfigurationError with the class name in the message.
        """
        raise InvalidConfigurationError(f'{type(self).__name__}: {msg}')

    def batch_advisories(self, advisories: List[Advisory]) -> Set[Advisory]:
        """
        Yield batches of the passed in list of advisories.
        """
        advisories = advisories[:]  # copy the list as we are mutating it in the loop below

        while advisories:
            b, advisories = advisories[:self.config.batch_size], advisories[self.config.batch_size:]
            yield set(b)


@dataclasses.dataclass
class GitDataSourceConfiguration(DataSourceConfiguration):
    repository_url: str
    branch: Optional[str] = None
    create_working_directory: bool = True
    remove_working_directory: bool = True
    working_directory: Optional[str] = None


class GitDataSource(DataSource):
    CONFIG_CLASS = GitDataSourceConfiguration

    def validate_configuration(self) -> None:

        if not self.config.create_working_directory and self.config.working_directory is None:
            self.error('"create_working_directory" is not set but "working_directory" is set to '
                       'the default, which calls tempfile.mkdtemp()')

        if not self.config.create_working_directory and \
                not os.path.exists(self.config.working_directory):
            self.error('"working_directory" does not contain an existing directory and'
                       '"create_working_directory" is not set')

        if not self.config.remove_working_directory and self.config.working_directory is None:
            self.error('"remove_working_directory" is not set and "working_directory" is set to '
                       'the default, which calls tempfile.mkdtemp()')

    def __enter__(self):
        self._ensure_working_directory()
        self._ensure_repository()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.config.remove_working_directory:
            shutil.rmtree(self.config.working_directory)

    def file_changes(
            self,
            subdir: str = None,
            recursive: bool = False,
            file_ext: Optional[str] = None,
    ) -> Tuple[Set[str], Set[str]]:
        """
        Returns all added and modified files since last_run_date or cutoff_date (whichever is more
        recent).

        :param subdir: filter by files in this directory
        :param recursive: whether to include files in subdirectories
        :param file_ext: filter files by this extension
        :return: The first set contains (absolute paths to) added files, the second one modified
                 files
        """
        if subdir is None:
            working_dir = self.config.working_directory
        else:
            working_dir = os.path.join(self.config.working_directory, subdir)

        path = Path(working_dir)

        if self.config.last_run_date is None and self.config.cutoff_date is None:
            if recursive:
                glob = '**/*'
            else:
                glob = '*'

            if file_ext:
                glob = f'{glob}.{file_ext}'

            return {str(p) for p in path.glob(glob) if p.is_file()}, set()

        return self._collect_file_changes(subdir=subdir, recursive=recursive, file_ext=file_ext)

    def _collect_file_changes(
            self,
            subdir: Optional[str],
            recursive: bool,
            file_ext: Optional[str],
    ) -> Tuple[Set[str], Set[str]]:

        previous_commit = None
        added_files, updated_files = set(), set()

        for commit in self._repo.walk(self._repo.head.target, pygit2.GIT_SORT_TIME):
            commit_time = commit.commit_time + commit.commit_time_offset  # convert to UTC

            if commit_time < self.cutoff_timestamp:
                break

            if previous_commit is None:
                previous_commit = commit
                continue

            for d in commit.tree.diff_to_tree(previous_commit.tree).deltas:
                if not _include_file(d.new_file.path, subdir, recursive, file_ext) or d.is_binary:
                    continue

                abspath = os.path.join(self.config.working_directory, d.new_file.path)
                # TODO
                # Just filtering on the two status values for "added" and "modified" is too
                # simplistic. This does not cover file renames, copies & deletions.
                if d.status == pygit2.GIT_DELTA_ADDED:
                    added_files.add(abspath)
                elif d.status == pygit2.GIT_DELTA_MODIFIED:
                    updated_files.add(abspath)

            previous_commit = commit

        # Any file that has been added and then updated inside the window of the git history we
        # looked at, should be considered "added", not "updated", since it does not exist in the
        # database yet.
        updated_files = updated_files - added_files

        return added_files, updated_files

    def _ensure_working_directory(self) -> None:
        if self.config.working_directory is None:
            self.config.working_directory = tempfile.mkdtemp()
        elif self.config.create_working_directory and \
                not os.path.exists(self.config.working_directory):
            os.mkdir(self.config.working_directory)

    def _ensure_repository(self) -> None:
        repodir = pygit2.discover_repository(self.config.working_directory)
        if repodir is None:
            self._clone_repository()
            return

        self._repo = pygit2.Repository(repodir)

        if self.config.branch is None:
            self.config.branch = self._repo.head.shorthand
        branch = self._repo.branches[self.config.branch]

        if not branch.is_checked_out():
            self._repo.checkout(branch)

        remote = self._find_or_add_remote()
        self._update_from_remote(remote, branch)

    def _clone_repository(self) -> None:
        kwargs = {}
        if getattr(self, 'branch', False):
            kwargs['checkout_branch'] = self.config.branch

        self._repo = pygit2.clone_repository(
            self.config.repository_url,
            self.config.working_directory,
            **kwargs
        )

    def _find_or_add_remote(self):
        remote = None
        for r in self._repo.remotes:
            if r.url == self.config.repository_url:
                remote = r
                break

        if remote is None:
            remote = self._repo.remotes.create(
                'added_by_vulnerablecode', self.config.repository_url)

        return remote

    def _update_from_remote(self, remote, branch) -> None:
        progress = remote.fetch()
        if progress.received_objects == 0:
            return

        remote_branch = self._repo.branches[f'{remote.name}/{self.config.branch}']
        branch.set_target(remote_branch.target)
        self._repo.checkout(branch, strategy=pygit2.GIT_CHECKOUT_FORCE)


def _include_file(
        path: str,
        subdir: Optional[str] = None,
        recursive: bool = False,
        file_ext: Optional[str] = None,
) -> bool:
    match = True

    if subdir:
        if not subdir.endswith(os.path.sep):
            subdir = f'{subdir}{os.path.sep}'

        match = match and path.startswith(subdir)

    if not recursive:
        match = match and (os.path.sep not in path[len(subdir or ''):])

    if file_ext:
        match = match and path.endswith(f'.{file_ext}')

    return match
