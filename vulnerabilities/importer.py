#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import dataclasses
import datetime
import logging
import os
import shutil
import traceback
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional
from typing import Set
from typing import Tuple

import pytz
from dateutil import parser as dateparser
from fetchcode.vcs import VCSResponse
from fetchcode.vcs import fetch_via_vcs
from license_expression import Licensing
from packageurl import PackageURL
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.version_range import VersionRange
from univers.versions import Version

from vulnerabilities import severity_systems
from vulnerabilities.oval_parser import OvalParser
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.severity_systems import ScoringSystem
from vulnerabilities.utils import classproperty
from vulnerabilities.utils import evolve_purl
from vulnerabilities.utils import get_reference_id
from vulnerabilities.utils import is_cve
from vulnerabilities.utils import nearest_patched_package

logger = logging.getLogger(__name__)


@dataclasses.dataclass(order=True)
class VulnerabilitySeverity:
    # FIXME: this should be named scoring_system, like in the model
    system: ScoringSystem
    value: str
    scoring_elements: str = ""

    def to_dict(self):
        return {
            "system": self.system.identifier,
            "value": self.value,
            "scoring_elements": self.scoring_elements,
        }

    @classmethod
    def from_dict(cls, severity: dict):
        """
        Return a VulnerabilitySeverity object from a ``severity`` mapping of
        VulnerabilitySeverity data.
        """
        return cls(
            system=SCORING_SYSTEMS[severity["system"]],
            value=severity["value"],
            scoring_elements=severity.get("scoring_elements", ""),
        )


@dataclasses.dataclass(order=True)
class Reference:

    reference_id: str = ""
    url: str = ""
    severities: List[VulnerabilitySeverity] = dataclasses.field(default_factory=list)

    def __post_init__(self):
        if not self.url:
            raise TypeError("Reference must have a url")

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

    @classmethod
    def from_url(cls, url):
        reference_id = get_reference_id(url)
        if "GHSA-" in reference_id.upper():
            return cls(reference_id=reference_id, url=url)
        if is_cve(reference_id):
            return cls(url=url, reference_id=reference_id.upper())
        return cls(url=url)


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
    def merge(
        cls, affected_packages: Iterable
    ) -> Tuple[PackageURL, List[VersionRange], List[Version]]:
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
    summary: Optional[str] = ""
    affected_packages: List[AffectedPackage] = dataclasses.field(default_factory=list)
    references: List[Reference] = dataclasses.field(default_factory=list)
    date_published: Optional[datetime.datetime] = None
    weaknesses: List[int] = dataclasses.field(default_factory=list)

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
            "weaknesses": self.weaknesses,
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
            "date_published": datetime.datetime.fromisoformat(date_published)
            if date_published
            else None,
            "weaknesses": advisory_data["weaknesses"],
        }
        return cls(**transformed)


class NoLicenseError(Exception):
    pass


class InvalidSPDXLicense(Exception):
    pass


class ForkError(Exception):
    pass


class Importer:
    """
    An Importer collects data from various upstreams and returns corresponding AdvisoryData objects
    in its advisory_data method.  Subclass this class to implement an importer
    """

    spdx_license_expression = ""
    license_url = ""
    notice = ""
    vcs_response: VCSResponse = None

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

    def clone(self, repo_url):
        """
        Clone the repo at repo_url and return the VCSResponse object
        """
        try:
            self.vcs_response = fetch_via_vcs(repo_url)
            return self.vcs_response
        except Exception as e:
            msg = f"Failed to fetch {repo_url} via vcs: {e}"
            logger.error(msg)
            raise ForkError(msg) from e


# TODO: Needs rewrite
class OvalImporter(Importer):
    """
    All data sources which collect data from OVAL files must inherit from this
    `OvalDataSource` class. Subclasses must implement the methods `_fetch` and `set_api`.
    """

    @staticmethod
    def create_purl(pkg_name: str, pkg_data: Mapping) -> PackageURL:
        """
        Helper method for creating different purls for subclasses without them reimplementing
        get_data_from_xml_doc  method
        Note: pkg_data must include 'type' of package
        """
        return PackageURL(name=pkg_name, **pkg_data)

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
                yield from oval_data
            except Exception:
                logger.error(
                    f"Failed to get updated_advisories: {oval_file!r} "
                    f"with {metadata!r}:\n" + traceback.format_exc()
                )
                continue

    def get_data_from_xml_doc(
        self, xml_doc: ET.ElementTree, pkg_metadata={}
    ) -> Iterable[AdvisoryData]:
        """
        The orchestration method of the OvalDataSource. This method breaks an
        OVAL xml ElementTree into a list of `Advisory`.

        Note: pkg_metadata is a mapping of Package URL data that MUST INCLUDE
        "type" key.

        Example value of pkg_metadata:
                {"type":"deb","qualifiers":{"distro":"buster"} }
        """
        oval_parsed_data = OvalParser(self.translations, xml_doc)
        raw_data = oval_parsed_data.get_data()
        oval_doc = oval_parsed_data.oval_document
        timestamp = oval_doc.getGenerator().getTimestamp()

        # convert definition_data to Advisory objects
        for definition_data in raw_data:
            # These fields are definition level, i.e common for all elements
            # connected/linked to an OvalDefinition
            vuln_id = definition_data["vuln_id"]
            description = definition_data["description"]

            severities = []
            severity = definition_data.get("severity")
            if severity:
                severities.append(
                    VulnerabilitySeverity(system=severity_systems.GENERIC, value=severity)
                )
            references = [
                Reference(url=url, severities=severities)
                for url in definition_data["reference_urls"]
            ]
            affected_packages = []
            for test_data in definition_data["test_data"]:
                for package_name in test_data["package_list"]:
                    affected_version_range = test_data["version_ranges"]
                    vrc = RANGE_CLASS_BY_SCHEMES[pkg_metadata["type"]]
                    if affected_version_range:
                        try:
                            affected_version_range = vrc.from_native(affected_version_range)
                        except Exception as e:
                            logger.error(
                                f"Failed to parse version range {affected_version_range!r} "
                                f"for package {package_name!r}:\n{e}"
                            )
                            continue
                    if package_name:
                        affected_packages.append(
                            AffectedPackage(
                                package=self.create_purl(package_name, pkg_metadata),
                                affected_version_range=affected_version_range,
                            )
                        )
            date_published = dateparser.parse(timestamp)
            if not date_published.tzinfo:
                date_published = date_published.replace(tzinfo=pytz.UTC)
            yield AdvisoryData(
                aliases=[vuln_id],
                summary=description,
                affected_packages=affected_packages,
                references=sorted(references),
                date_published=date_published,
            )
