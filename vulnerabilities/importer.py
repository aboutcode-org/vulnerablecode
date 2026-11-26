#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import dataclasses
import datetime
import functools
import logging
import traceback
import xml.etree.ElementTree as ET
from typing import List
from typing import Optional

from packageurl import PackageURL
from univers.version_range import VersionRange

from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.severity_systems import ScoringSystem
from vulnerabilities.utils import compute_patch_checksum
from vulnerabilities.utils import get_reference_id
from vulnerabilities.utils import is_commit
from vulnerabilities.utils import is_cve
from vulnerabilities.utils import purl_to_dict

logger = logging.getLogger(__name__)


@dataclasses.dataclass(eq=True)
@functools.total_ordering
class VulnerabilitySeverity:
    # FIXME: this should be named scoring_system, like in the model
    system: ScoringSystem
    value: str
    scoring_elements: str = ""
    published_at: Optional[datetime.datetime] = None
    url: Optional[str] = None

    def __post_init__(self):
        if not self.system:
            raise ValueError("system is required for VulnerabilitySeverity")

        if not isinstance(self.system, ScoringSystem):
            raise TypeError(f"system must be a ScoringSystem, got {type(self.system)!r}")

        if not isinstance(self.value, str):
            self.value = str(self.value) if self.value else ""

    def to_dict(self):
        data = {
            "system": self.system.identifier,
            "value": self.value,
            "scoring_elements": self.scoring_elements,
        }
        if self.published_at:
            if isinstance(self.published_at, datetime.datetime):
                data["published_at"] = self.published_at.isoformat()
            else:
                data["published_at"] = self.published_at
        return data

    def __lt__(self, other):
        if not isinstance(other, VulnerabilitySeverity):
            return NotImplemented
        return self._cmp_key() < other._cmp_key()

    # TODO: Add cache
    def _cmp_key(self):
        return (self.system.identifier, self.value, self.scoring_elements, self.published_at)

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
            published_at=severity.get("published_at"),
        )


@dataclasses.dataclass(eq=True)
@functools.total_ordering
class ReferenceV2:
    reference_id: str = ""
    reference_type: str = ""
    url: str = ""

    def __post_init__(self):
        if not self.url:
            raise TypeError("Reference must have a url")
        if self.reference_id and not isinstance(self.reference_id, str):
            self.reference_id = str(self.reference_id)

    def __lt__(self, other):
        if not isinstance(other, ReferenceV2):
            return NotImplemented
        return self._cmp_key() < other._cmp_key()

    # TODO: Add cache
    def _cmp_key(self):
        return (self.reference_id, self.reference_type, self.url)

    def to_dict(self):
        """Return a normalized dictionary representation"""
        return {
            "reference_id": self.reference_id,
            "reference_type": self.reference_type,
            "url": self.url,
        }

    @classmethod
    def from_dict(cls, ref: dict):
        return cls(
            reference_id=str(ref["reference_id"]),
            reference_type=ref.get("reference_type") or "",
            url=ref["url"],
        )

    @classmethod
    def from_url(cls, url):
        reference_id = get_reference_id(url)
        if "GHSA-" in reference_id.upper():
            return cls(reference_id=reference_id, url=url)
        if reference_id.startswith(("RHSA-", "RHEA-", "RHBA-")):
            return cls(reference_id=reference_id, url=url)
        if is_cve(reference_id):
            return cls(url=url, reference_id=reference_id.upper())
        return cls(url=url)


@dataclasses.dataclass(eq=True)
@functools.total_ordering
class PackageCommitPatchData:
    vcs_url: str
    commit_hash: str
    patch_text: Optional[str] = None
    patch_checksum: Optional[str] = dataclasses.field(init=False, default=None)

    def __post_init__(self):
        if not self.commit_hash:
            raise ValueError("Commit must have a non-empty commit_hash.")

        if not is_commit(self.commit_hash):
            raise ValueError(f"Commit must be a valid a commit_hash: {self.commit_hash}.")

        if not self.vcs_url:
            raise ValueError("Commit must have a non-empty vcs_url.")

        if self.patch_text:
            self.patch_checksum = compute_patch_checksum(self.patch_text)

    def __lt__(self, other):
        if not isinstance(other, PackageCommitPatchData):
            return NotImplemented
        return self._cmp_key() < other._cmp_key()

    # TODO: Add cache
    def _cmp_key(self):
        return (
            self.vcs_url,
            self.commit_hash,
            self.patch_text,
            self.patch_checksum,
        )

    def to_dict(self) -> dict:
        """Return a normalized dictionary representation of the commit."""
        return {
            "vcs_url": self.vcs_url,
            "commit_hash": self.commit_hash,
            "patch_text": self.patch_text,
            "patch_checksum": self.patch_checksum,
        }

    @classmethod
    def from_dict(cls, data: dict):
        """Create a PackageCommitPatchData instance from a dictionary."""
        return cls(
            vcs_url=data.get("vcs_url"),
            commit_hash=data.get("commit_hash"),
            patch_text=data.get("patch_text"),
        )


@dataclasses.dataclass(eq=True)
@functools.total_ordering
class PatchData:
    patch_url: Optional[str] = ""
    patch_text: Optional[str] = ""
    patch_checksum: Optional[str] = dataclasses.field(init=False, default=None)

    def __post_init__(self):
        if not self.patch_url and not self.patch_text:
            raise ValueError("A patch must include either patch_url or patch_text")

        if self.patch_text:
            self.patch_checksum = compute_patch_checksum(self.patch_text)

    def __lt__(self, other):
        if not isinstance(other, PatchData):
            return NotImplemented
        return self._cmp_key() < other._cmp_key()

    def _cmp_key(self):
        return (
            self.patch_url or "",
            self.patch_text or "",
            self.patch_checksum or "",
        )

    def to_dict(self) -> dict:
        """Return a normalized dictionary representation of the commit."""
        return {
            "patch_url": self.patch_url,
            "patch_text": self.patch_text,
            "patch_checksum": self.patch_checksum,
        }

    @classmethod
    def from_dict(cls, data: dict):
        """Create a PatchData instance from a dictionary."""
        return cls(
            patch_url=data.get("patch_url"),
            patch_text=data.get("patch_text"),
        )


class UnMergeablePackageError(Exception):
    """
    Raised when a package cannot be merged with another one.
    """


class NoAffectedPackages(Exception):
    """
    Raised when there were no affected packages found.
    """


@functools.total_ordering
@dataclasses.dataclass(eq=True)
class AffectedPackageV2:
    """
    Relate a Package URL with a range of affected versions and fixed versions.
    The Package URL must *not* have a version.
    AffectedPackage must contain either ``affected_version_range`` or ``fixed_version_range`` or ``introduced_by_commits`` or ``fixed_by_commits``.
    """

    package: PackageURL
    affected_version_range: Optional[VersionRange] = None
    fixed_version_range: Optional[VersionRange] = None
    introduced_by_commit_patches: List[PackageCommitPatchData] = dataclasses.field(
        default_factory=list
    )
    fixed_by_commit_patches: List[PackageCommitPatchData] = dataclasses.field(default_factory=list)

    def __post_init__(self):
        if self.package.version:
            raise ValueError(f"Affected Package URL {self.package!r} cannot have a version.")

        if not (
            self.affected_version_range
            or self.fixed_version_range
            or self.introduced_by_commit_patches
            or self.fixed_by_commit_patches
        ):
            raise ValueError(
                f"Affected package {self.package!r} must have either a fixed version range, "
                "an affected version range, introduced commit patches, or fixed commit patches."
            )

        if self.affected_version_range is not None and not isinstance(
            self.affected_version_range, VersionRange
        ):
            raise TypeError(
                f"affected_version_range must be VersionRange or None, got {type(self.affected_version_range)!r}"
            )

        if self.fixed_version_range is not None and not isinstance(
            self.fixed_version_range, VersionRange
        ):
            raise TypeError(
                f"fixed_version_range must be VersionRange or None, got {type(self.fixed_version_range)!r}"
            )

        if not isinstance(self.introduced_by_commit_patches, list):
            raise TypeError(
                f"introduced_by_commit_patches must be a list, got {type(self.introduced_by_commit_patches)!r}"
            )

        if not isinstance(self.fixed_by_commit_patches, list):
            raise TypeError(
                f"fixed_by_commit_patches must be a list, got {type(self.fixed_by_commit_patches)!r}"
            )

        for item in self.introduced_by_commit_patches:
            if not isinstance(item, PackageCommitPatchData):
                raise TypeError(
                    f"introduced_by_commit_patches items must be PackageCommitPatchData, got {type(item)!r}"
                )

        for item in self.fixed_by_commit_patches:
            if not isinstance(item, PackageCommitPatchData):
                raise TypeError(
                    f"fixed_by_commit_patches items must be PackageCommitPatchData, got {type(item)!r}"
                )

    def __lt__(self, other):
        if not isinstance(other, AffectedPackageV2):
            return NotImplemented
        return self._cmp_key() < other._cmp_key()

    # TODO: Add cache
    def _cmp_key(self):
        return (
            str(self.package),
            str(self.affected_version_range or ""),
            str(self.fixed_version_range or ""),
            str(self.introduced_by_commit_patches or []),
            str(self.fixed_by_commit_patches or []),
        )

    def to_dict(self):
        """Return a serializable dict that can be converted back using self.from_dict"""

        affected_version_range = (
            str(self.affected_version_range) if self.affected_version_range else None
        )
        fixed_version_range = str(self.fixed_version_range) if self.fixed_version_range else None
        return {
            "package": purl_to_dict(self.package),
            "affected_version_range": affected_version_range,
            "fixed_version_range": fixed_version_range,
            "introduced_by_commit_patches": [
                commit.to_dict() for commit in self.introduced_by_commit_patches
            ],
            "fixed_by_commit_patches": [
                commit.to_dict() for commit in self.fixed_by_commit_patches
            ],
        }

    @classmethod
    def from_dict(cls, affected_pkg: dict):
        """Return an AffectedPackage object from dict generated by self.to_dict"""

        package = PackageURL(**affected_pkg["package"])
        affected_version_range = None
        fixed_version_range = None
        affected_range = affected_pkg["affected_version_range"]
        fixed_range = affected_pkg["fixed_version_range"]
        introduced_by_commit_patches = affected_pkg.get("introduced_by_commit_patches") or []
        fixed_by_commit_patches = affected_pkg.get("fixed_by_commit_patches") or []

        try:
            affected_version_range = (
                VersionRange.from_string(affected_range) if affected_range else None
            )
            fixed_version_range = VersionRange.from_string(fixed_range) if fixed_range else None
        except:
            tb = traceback.format_exc()
            logger.error(
                f"Cannot create AffectedPackage with invalid or unknown range: {affected_pkg!r} with error: {tb!r}"
            )
            return

        if (
            not fixed_version_range
            and not affected_version_range
            and not introduced_by_commit_patches
            and not fixed_by_commit_patches
        ):
            logger.error(
                f"Cannot create an AffectedPackage for: {affected_pkg!r}, at least one of the following must be provided: "
                "a fixed version range, an affected version range, introduced commit patches, or fixed commit patches"
            )
            return

        return cls(
            package=package,
            affected_version_range=affected_version_range,
            fixed_version_range=fixed_version_range,
            introduced_by_commit_patches=[
                PackageCommitPatchData.from_dict(commit) for commit in introduced_by_commit_patches
            ],
            fixed_by_commit_patches=[
                PackageCommitPatchData.from_dict(commit) for commit in fixed_by_commit_patches
            ],
        )


@dataclasses.dataclass(order=True)
class AdvisoryDataV2:
    """
    This data class expresses the contract between data sources and the import runner.
    """

    advisory_id: str = ""
    aliases: List[str] = dataclasses.field(default_factory=list)
    summary: Optional[str] = ""
    affected_packages: List[AffectedPackageV2] = dataclasses.field(default_factory=list)
    references: List[ReferenceV2] = dataclasses.field(default_factory=list)
    patches: List[PatchData] = dataclasses.field(default_factory=list)
    date_published: Optional[datetime.datetime] = None
    weaknesses: List[int] = dataclasses.field(default_factory=list)
    severities: List[VulnerabilitySeverity] = dataclasses.field(default_factory=list)
    url: Optional[str] = None
    original_advisory_text: Optional[str] = None

    def __post_init__(self):
        if not self.advisory_id:
            raise ValueError("advisory_id is required for AdvisoryDataV2")
        if self.advisory_id and self.advisory_id in self.aliases:
            raise ValueError(
                f"advisory_id {self.advisory_id} should not be present in aliases {self.aliases}"
            )
        if self.summary:
            self.summary = clean_summary(self.summary)

    def to_dict(self):
        return {
            "advisory_id": self.advisory_id,
            "aliases": self.aliases,
            "summary": self.summary,
            "affected_packages": [pkg.to_dict() for pkg in self.affected_packages],
            "references": [ref.to_dict() for ref in self.references],
            "patches": [patch.to_dict() for patch in self.patches],
            "severities": [sev.to_dict() for sev in self.severities],
            "date_published": self.date_published.isoformat() if self.date_published else None,
            "weaknesses": self.weaknesses,
            "url": self.url if self.url else "",
        }

    @classmethod
    def from_dict(cls, advisory_data):
        date_published = advisory_data["date_published"]
        transformed = {
            "advisory_id": advisory_data["advisory_id"],
            "aliases": advisory_data["aliases"],
            "summary": advisory_data["summary"],
            "affected_packages": [
                AffectedPackageV2.from_dict(pkg)
                for pkg in advisory_data["affected_packages"]
                if pkg is not None
            ],
            "patches": [PatchData.from_dict(patch) for patch in advisory_data.get("patches", [])],
            "references": [ReferenceV2.from_dict(ref) for ref in advisory_data["references"]],
            "date_published": (
                datetime.datetime.fromisoformat(date_published) if date_published else None
            ),
            "weaknesses": advisory_data["weaknesses"],
            "severities": [
                VulnerabilitySeverity.from_dict(sev) for sev in advisory_data.get("severities", [])
            ],
            "url": advisory_data.get("url") or None,
        }
        return cls(**transformed)


def clean_summary(summary):
    # https://nvd.nist.gov/vuln/detail/CVE-2013-4314
    # https://github.com/cms-dev/cms/issues/888#issuecomment-516977572
    summary = summary.strip()
    if summary:
        summary = summary.replace("\x00", "\uFFFD")
    return summary


class NoLicenseError(Exception):
    pass


class InvalidSPDXLicense(Exception):
    pass


class ForkError(Exception):
    pass
