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
import datetime
import logging
import os
import shutil
import tempfile
import traceback
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional
from typing import Set
from typing import Tuple

from binaryornot.helpers import is_binary_string
from git import DiffIndex
from git import Repo
from license_expression import Licensing
from packageurl import PackageURL
from univers.version_range import VersionRange
from univers.versions import Version

from vulnerabilities.helpers import classproperty
from vulnerabilities.helpers import evolve_purl
from vulnerabilities.helpers import nearest_patched_package
from vulnerabilities.oval_parser import OvalParser
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.severity_systems import ScoringSystem

logger = logging.getLogger(__name__)


@dataclasses.dataclass(order=True)
class VulnerabilitySeverity:
    system: ScoringSystem
    value: str

    def to_dict(self):
        return {
            "system": self.system.identifier,
            "value": self.value,
        }

    @classmethod
    def from_dict(cls, severity: dict):
        """
        Return a VulnerabilitySeverity object from a ``severity`` mapping of
        VulnerabilitySeverity data.
        """
        return cls(system=SCORING_SYSTEMS[severity["system"]], value=severity["value"])


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

    def to_dict(self):
        return {
            "reference_id": self.reference_id,
            "url": self.url,
            "severities": [severity.to_dict() for severity in self.severities],
        }

    @classmethod
    def from_dict(cls, ref: dict):
        return cls(
            reference_id=ref["reference_id"],
            url=ref["url"],
            severities=[
                VulnerabilitySeverity.from_dict(severity) for severity in ref["severities"]
            ],
        )


class UnMergeablePackageError(Exception):
    """
    Raised when a package cannot be merged with another one.
    """


class NoAffectedPackages(Exception):
    """
    Raised when there were no affected packages found.
    """


@dataclasses.dataclass(order=True, frozen=True)
class AffectedPackage:
    """
    Relate a Package URL with a range of affected versions and a fixed version.
    The Package URL must *not* have a version.
    AffectedPackage must contain either ``affected_version_range`` or ``fixed_version``.
    """

    package: PackageURL
    affected_version_range: Optional[VersionRange] = None
    fixed_version: Optional[Version] = None

    def __post_init__(self):
        if self.package.version:
            raise ValueError(f"Affected Package URL {self.package!r} cannot have a version.")

        if not (self.affected_version_range or self.fixed_version):
            raise ValueError(
                f"Affected Package {self.package!r} should have either a fixed version or an "
                "affected version range."
            )

    def get_fixed_purl(self):
        """
        Return a Package URL corresponding to object's fixed_version
        """
        if not self.fixed_version:
            raise ValueError(f"Affected Package {self.package!r} does not have a fixed version")
        fixed_purl = evolve_purl(purl=self.package, version=str(self.fixed_version))
        return fixed_purl

    @classmethod
    def merge(cls, affected_packages: Iterable):
        """
        Return a tuple with all attributes of AffectedPackage as a set
        for all values in the given iterable of AffectedPackage

        This is useful where an iterable of AffectedPackage needs to be
        converted into one tuple of structure similar to AffectedPackage
        but with multiple fixed_versions, ie
            package: PackageURL
            affected_version_range: set(VersionRange)
            fixed_versions: set(Version)
        """
        affected_packages = list(affected_packages)
        if not affected_packages:
            raise NoAffectedPackages("No affected packages found")
        affected_version_ranges = list()
        fixed_versions = list()
        purls = set()
        for pkg in affected_packages:
            if pkg.affected_version_range:
                if pkg.affected_version_range not in affected_version_ranges:
                    affected_version_ranges.append(pkg.affected_version_range)
            if pkg.fixed_version:
                if pkg.fixed_version not in fixed_versions:
                    fixed_versions.append(pkg.fixed_version)
            purls.add(pkg.package)
        if len(purls) > 1:
            raise UnMergeablePackageError("Cannot merge with different purls", purls)
        return purls.pop(), sorted(affected_version_ranges), sorted(fixed_versions)

    def to_dict(self):
        """
        Return a serializable dict that can be converted back using self.from_dict
        """
        affected_version_range = None
        if self.affected_version_range:
            affected_version_range = str(self.affected_version_range)
        return {
            "package": self.package.to_dict(),
            "affected_version_range": affected_version_range,
            "fixed_version": str(self.fixed_version) if self.fixed_version else None,
        }

    @classmethod
    def from_dict(cls, affected_pkg: dict):
        """
        Return an AffectedPackage object from dict generated by self.to_dict
        """
        package = PackageURL(**affected_pkg["package"])
        affected_version_range = None
        if (
            affected_pkg["affected_version_range"]
            and affected_pkg["affected_version_range"] != "None"
        ):
            affected_version_range = VersionRange.from_string(
                affected_pkg["affected_version_range"]
            )
        fixed_version = affected_pkg["fixed_version"]
        if fixed_version and affected_version_range:
            # TODO: revisit after https://github.com/nexB/univers/issues/10
            fixed_version = affected_version_range.version_class(fixed_version)

        return cls(
            package=package,
            affected_version_range=affected_version_range,
            fixed_version=fixed_version,
        )


@dataclasses.dataclass(order=True)
class AdvisoryData:
    """
    This data class expresses the contract between data sources and the import runner.

    If a vulnerability_id is present then:
        summary or affected_packages or references must be present
    otherwise
        either affected_package or references should be present

    date_published must be aware datetime
    """

    aliases: List[str] = dataclasses.field(default_factory=list)
    summary: Optional[str] = None
    affected_packages: List[AffectedPackage] = dataclasses.field(default_factory=list)
    references: List[Reference] = dataclasses.field(default_factory=list)
    date_published: Optional[datetime.datetime] = None

    def __post_init__(self):
        if self.date_published and not self.date_published.tzinfo:
            logger.warning(f"AdvisoryData with no tzinfo: {self!r}")

    def to_dict(self):
        return {
            "aliases": self.aliases,
            "summary": self.summary,
            "affected_packages": [pkg.to_dict() for pkg in self.affected_packages],
            "references": [ref.to_dict() for ref in self.references],
            "date_published": self.date_published.isoformat() if self.date_published else None,
        }

    @classmethod
    def from_dict(cls, advisory_data):
        date_published = advisory_data["date_published"]
        transformed = {
            "aliases": advisory_data["aliases"],
            "summary": advisory_data["summary"],
            "affected_packages": [
                AffectedPackage.from_dict(pkg) for pkg in advisory_data["affected_packages"]
            ],
            "references": [Reference.from_dict(ref) for ref in advisory_data["references"]],
            "date_published": date_published.isoformat() if date_published else None,
        }
        return cls(**transformed)


class NoLicenseError(Exception):
    pass


class InvalidSPDXLicense(Exception):
    pass


class Importer:
    """
    An Importer collects data from various upstreams and returns corresponding AdvisoryData objects
    in its advisory_data method.  Subclass this class to implement an importer
    """

    spdx_license_expression = ""
    license_url = ""

    def __init__(self):
        if not self.spdx_license_expression:
            raise Exception(f"Cannot run importer {self!r} without a license")
        licensing = Licensing()
        try:
            licensing.parse(self.spdx_license_expression)
        except InvalidSPDXLicense as e:
            raise ValueError(
                f"{self.spdx_license_expression!r} is not a valid SPDX license expression"
            ) from e

    @classproperty
    def qualified_name(cls):
        """
        Fully qualified name prefixed with the module name of the improver used in logging.
        """
        return f"{cls.__module__}.{cls.__qualname__}"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        """
        Return AdvisoryData objects corresponding to the data being imported
        """
        raise NotImplementedError


# TODO: Needs rewrite
class GitImporter(Importer):
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


# TODO: Needs rewrite
class OvalImporter(Importer):
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

    def advisory_data(self) -> List[AdvisoryData]:
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

    def get_data_from_xml_doc(self, xml_doc: ET.ElementTree, pkg_metadata={}) -> List[AdvisoryData]:
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

                    affected_version_range = VersionRange.from_scheme_version_spec_string(
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
                AdvisoryData(
                    summary=description,
                    affected_packages=affected_packages,
                    vulnerability_id=vuln_id,
                    references=references,
                )
            )
        return all_adv
