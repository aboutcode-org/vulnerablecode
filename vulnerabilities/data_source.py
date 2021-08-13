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
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import dataclasses
import logging
import os
import shutil
import tempfile
import traceback
import xml.etree.ElementTree as ET
from binaryornot.helpers import is_binary_string
from datetime import datetime
from pathlib import Path
from typing import Any
from typing import ContextManager
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional
from typing import Set
from typing import Tuple
from git import Repo, DiffIndex
from packageurl import PackageURL
from univers.version_specifier import VersionSpecifier
from univers.versions import version_class_by_package_type

from vulnerabilities.oval_parser import OvalParser
from vulnerabilities.severity_systems import ScoringSystem
from vulnerabilities.helpers import is_cve
from vulnerabilities.helpers import nearest_patched_package
from vulnerabilities.helpers import AffectedPackage

logger = logging.getLogger(__name__)


@dataclasses.dataclass(order=True)
class VulnerabilitySeverity:
    system: ScoringSystem
    value: str


@dataclasses.dataclass(order=True)
class Reference:

    reference_id: str = ""
    url: str = ""
    severities: List[VulnerabilitySeverity] = dataclasses.field(default_factory=list)

    def __post_init__(self):
        if not any([self.url, self.reference_id]):
            raise TypeError

    def normalized(self):
        severities = sorted(self.severities)
        return Reference(reference_id=self.reference_id, url=self.url, severities=severities)


@dataclasses.dataclass(order=True)
class Advisory:
    """
    This data class expresses the contract between data sources and the import runner.

    NB: There are two representations for package URLs that are commonly used by code consuming this
        data class; PackageURL objects and strings. As a convention, the former is referred to in
        variable names, etc. as "package_urls" and the latter as "purls".
    """

    summary: str
    vulnerability_id: Optional[str] = None
    affected_package_urls: Iterable[PackageURL] = dataclasses.field(default_factory=list)
    fixed_package_urls: Iterable[PackageURL] = dataclasses.field(default_factory=list)
    references: List[Reference] = dataclasses.field(default_factory=list)

    def __post_init__(self):
        if self.vulnerability_id and not is_cve(self.vulnerability_id):
            raise ValueError("CVE expected, found: {}".format(self.vulnerability_id))

    def normalized(self):
        affected_package_urls = set(self.affected_package_urls)
        fixed_package_urls = set(self.fixed_package_urls)
        references = sorted(
            self.references, key=lambda reference: (reference.reference_id, reference.url)
        )
        for index, _ in enumerate(self.references):
            references[index] = references[index].normalized()

        return Advisory(
            summary=self.summary,
            vulnerability_id=self.vulnerability_id,
            affected_package_urls=affected_package_urls,
            fixed_package_urls=fixed_package_urls,
            references=references,
        )


class InvalidConfigurationError(Exception):
    pass


@dataclasses.dataclass
class DataSourceConfiguration:
    pass


class DataSource(ContextManager):
    """
    This class defines how importers consume advisories from a data source.

    It makes a distinction between newly added records since the last run and modified records. This
    allows the import logic to pick appropriate database operations.
    """

    CONFIG_CLASS = DataSourceConfiguration

    def __init__(
        self,
        last_run_date: Optional[datetime] = None,
        cutoff_date: Optional[datetime] = None,
        config: Optional[Mapping[str, Any]] = None,
    ):
        """
        Create a DataSource instance.

        :param last_run_date: Optional timestamp when this data source was last inspected
        :param cutoff_date: Optional timestamp, records older than this will be ignored
        :param config: Optional dictionary with subclass-specific configuration
        """
        config = config or {}
        try:
            self.config = self.__class__.CONFIG_CLASS(**config)
            # These really should be declared in DataSourceConfiguration above but that would
            # prevent DataSource subclasses from declaring mandatory parameters (i.e. positional
            # arguments)
            setattr(self.config, "last_run_date", last_run_date)
            setattr(self.config, "cutoff_date", cutoff_date)
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
        if not hasattr(self, "_cutoff_timestamp"):
            last_run = 0
            if self.config.last_run_date is not None:
                last_run = int(self.config.last_run_date.timestamp())

            cutoff = 0
            if self.config.cutoff_date is not None:
                cutoff = int(self.config.cutoff_date.timestamp())

            setattr(self, "_cutoff_timestamp", max(last_run, cutoff))

        return self._cutoff_timestamp

    def validate_configuration(self) -> None:
        """
        Subclasses can perform more complex validation than what is handled by data classes and
        their type annotations.

        This method is called in the constructor. It should raise InvalidConfigurationError with a
        human-readable message.
        """
        pass

    def updated_advisories(self) -> Set[Advisory]:
        """
        Subclasses return Advisory objects that have been modified since
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
        raise InvalidConfigurationError(f"{type(self).__name__}: {msg}")

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
            self.error(
                '"create_working_directory" is not set but "working_directory" is set to '
                "the default, which calls tempfile.mkdtemp()"
            )

        if not self.config.create_working_directory and not os.path.exists(
            self.config.working_directory
        ):
            self.error(
                '"working_directory" does not contain an existing directory and'
                '"create_working_directory" is not set'
            )

        if not self.config.remove_working_directory and self.config.working_directory is None:
            self.error(
                '"remove_working_directory" is not set and "working_directory" is set to '
                "the default, which calls tempfile.mkdtemp()"
            )

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
                glob = "**/*"
            else:
                glob = "*"

            if file_ext:
                glob = f"{glob}.{file_ext}"

            return {str(p) for p in path.glob(glob) if p.is_file()}, set()

        return self._collect_file_changes(subdir=subdir, recursive=recursive, file_ext=file_ext)

    def _collect_file_changes(
        self,
        subdir: Optional[str],
        recursive: bool,
        file_ext: Optional[str],
    ) -> Tuple[Set[str], Set[str]]:

        added_files, updated_files = set(), set()

        # find the most ancient commit we need to diff with
        cutoff_commit = None
        for commit in self._repo.iter_commits(self._repo.head):
            if commit.committed_date < self.cutoff_timestamp:
                break
            cutoff_commit = commit

        if cutoff_commit is None:
            return added_files, updated_files

        def _is_binary(d: DiffIndex):
            return is_binary_string(d.b_blob.data_stream.read(1024))

        for d in cutoff_commit.diff(self._repo.head.commit):
            if not _include_file(d.b_path, subdir, recursive, file_ext) or _is_binary(d):
                continue

            abspath = os.path.join(self.config.working_directory, d.b_path)
            if d.new_file:
                added_files.add(abspath)
            elif d.a_blob and d.b_blob:
                if d.a_path != d.b_path:
                    # consider moved files as added
                    added_files.add(abspath)
                elif d.a_blob != d.b_blob:
                    updated_files.add(abspath)

        # Any file that has been added and then updated inside the window of the git history we
        # looked at, should be considered "added", not "updated", since it does not exist in the
        # database yet.
        updated_files = updated_files - added_files

        return added_files, updated_files

    def _ensure_working_directory(self) -> None:
        if self.config.working_directory is None:
            self.config.working_directory = tempfile.mkdtemp()
        elif self.config.create_working_directory and not os.path.exists(
            self.config.working_directory
        ):
            os.mkdir(self.config.working_directory)

    def _ensure_repository(self) -> None:
        if not os.path.exists(os.path.join(self.config.working_directory, ".git")):
            self._clone_repository()
            return
        self._repo = Repo(self.config.working_directory)

        if self.config.branch is None:
            self.config.branch = str(self._repo.active_branch)
        branch = self.config.branch
        self._repo.head.reference = self._repo.heads[branch]
        self._repo.head.reset(index=True, working_tree=True)

        remote = self._find_or_add_remote()
        self._update_from_remote(remote, branch)

    def _clone_repository(self) -> None:
        kwargs = {}
        if self.config.branch:
            kwargs["branch"] = self.config.branch

        self._repo = Repo.clone_from(
            self.config.repository_url, self.config.working_directory, **kwargs
        )

    def _find_or_add_remote(self):
        remote = None
        for r in self._repo.remotes:
            if r.url == self.config.repository_url:
                remote = r
                break

        if remote is None:
            remote = self._repo.create_remote(
                "added_by_vulnerablecode", url=self.config.repository_url
            )

        return remote

    def _update_from_remote(self, remote, branch) -> None:
        fetch_info = remote.fetch()
        if len(fetch_info) == 0:
            return
        branch = self._repo.branches[branch]
        branch.set_reference(remote.refs[branch.name])
        self._repo.head.reset(index=True, working_tree=True)


def _include_file(
    path: str,
    subdir: Optional[str] = None,
    recursive: bool = False,
    file_ext: Optional[str] = None,
) -> bool:
    match = True

    if subdir:
        if not subdir.endswith(os.path.sep):
            subdir = f"{subdir}{os.path.sep}"

        match = match and path.startswith(subdir)

    if not recursive:
        match = match and (os.path.sep not in path[len(subdir or "") :])

    if file_ext:
        match = match and path.endswith(f".{file_ext}")

    return match


class OvalDataSource(DataSource):
    """
    All data sources which collect data from OVAL files must inherit from this
    `OvalDataSource` class. Subclasses must implement the methods `_fetch` and `set_api`.
    """

    @staticmethod
    def create_purl(pkg_name: str, pkg_version: str, pkg_data: Mapping) -> PackageURL:
        """
        Helper method for creating different purls for subclasses without them reimplementing
        get_data_from_xml_doc  method
        Note: pkg_data must include 'type' of package
        """
        return PackageURL(name=pkg_name, version=pkg_version, **pkg_data)

    @staticmethod
    def _collect_pkgs(parsed_oval_data: Mapping) -> Set:
        """
        Helper method, used for loading the API. It expects data from
        OvalParser.get_data().
        """
        all_pkgs = set()
        for definition_data in parsed_oval_data:
            for test_data in definition_data["test_data"]:
                for package in test_data["package_list"]:
                    all_pkgs.add(package)

        return all_pkgs

    def _fetch(self) -> Tuple[Mapping, Iterable[ET.ElementTree]]:
        """
        Return a two-tuple of ({mapping of Package URL data}, it's ET.ElementTree)
        Subclasses must implement this method.

        Note:  Package URL data MUST INCLUDE a Package URL "type" key so
        implement _fetch() accordingly.
        For example::

              {"type":"deb","qualifiers":{"distro":"buster"} }
        """
        # TODO: enforce that we receive the proper data here
        raise NotImplementedError

    def updated_advisories(self) -> List[Advisory]:
        for metadata, oval_file in self._fetch():
            try:
                oval_data = self.get_data_from_xml_doc(oval_file, metadata)
                yield oval_data
            except Exception:
                logger.error(
                    f"Failed to get updated_advisories: {oval_file!r} "
                    f"with {metadata!r}:\n" + traceback.format_exc()
                )
                continue

    def set_api(self, all_pkgs: Iterable[str]):
        """
        This method loads the self.pkg_manager_api with the specified packages.
        It fetches and caches all the versions of these packages and exposes
        them through self.pkg_manager_api.get(<package_name>). Example

        >> self.set_api(['electron'])
        Assume 'electron' has only versions 1.0.0 and 1.2.0
        >> assert  self.pkg_manager_api.get('electron') == {'1.0.0','1.2.0'}

        """
        raise NotImplementedError

    def get_data_from_xml_doc(self, xml_doc: ET.ElementTree, pkg_metadata={}) -> List[Advisory]:
        """
        The orchestration method of the OvalDataSource. This method breaks an
        OVAL xml ElementTree into a list of `Advisory`.

        Note: pkg_metadata is a mapping of Package URL data that MUST INCLUDE
        "type" key.

        Example value of pkg_metadata:
                {"type":"deb","qualifiers":{"distro":"buster"} }
        """

        all_adv = []
        oval_doc = OvalParser(self.translations, xml_doc)
        raw_data = oval_doc.get_data()
        all_pkgs = self._collect_pkgs(raw_data)
        self.set_api(all_pkgs)

        # convert definition_data to Advisory objects
        for definition_data in raw_data:
            # These fields are definition level, i.e common for all elements
            # connected/linked to an OvalDefinition
            vuln_id = definition_data["vuln_id"]
            description = definition_data["description"]
            references = [Reference(url=url) for url in definition_data["reference_urls"]]
            affected_packages = []
            for test_data in definition_data["test_data"]:
                for package_name in test_data["package_list"]:
                    if package_name and len(package_name) >= 50:
                        continue

                    affected_version_range = test_data["version_ranges"] or set()
                    version_class = version_class_by_package_type[pkg_metadata["type"]]
                    version_scheme = version_class.scheme

                    affected_version_range = VersionSpecifier.from_scheme_version_spec_string(
                        version_scheme, affected_version_range
                    )
                    all_versions = self.pkg_manager_api.get(package_name).valid_versions

                    # FIXME: what is this 50 DB limit? that's too small for versions
                    # FIXME: we should not drop data this way
                    # This filter is for filtering out long versions.
                    # 50 is limit because that's what db permits atm.
                    all_versions = [version for version in all_versions if len(version) < 50]
                    if not all_versions:
                        continue

                    affected_purls = []
                    safe_purls = []
                    for version in all_versions:
                        purl = self.create_purl(
                            pkg_name=package_name,
                            pkg_version=version,
                            pkg_data=pkg_metadata,
                        )
                        if version_class(version) in affected_version_range:
                            affected_purls.append(purl)
                        else:
                            safe_purls.append(purl)

                    affected_packages.extend(
                        nearest_patched_package(affected_purls, safe_purls),
                    )

            all_adv.append(
                Advisory(
                    summary=description,
                    affected_packages=affected_packages,
                    vulnerability_id=vuln_id,
                    references=references,
                )
            )
        return all_adv
