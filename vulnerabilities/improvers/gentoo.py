import logging
from typing import Iterable
from typing import List

import requests
from django.db.models import Q
from django.db.models.query import QuerySet
from packageurl import PackageURL
from univers.versions import GentooVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import UnMergeablePackageError
from vulnerabilities.importers.gentoo import GentooImporter
from vulnerabilities.improver import MAX_CONFIDENCE
from vulnerabilities.improver import Improver
from vulnerabilities.improver import Inference
from vulnerabilities.models import Advisory
from vulnerabilities.utils import AffectedPackage as LegacyAffectedPackage
from vulnerabilities.utils import get_affected_packages_by_patched_package
from vulnerabilities.utils import nearest_patched_package
from vulnerabilities.utils import resolve_version_range

logger = logging.getLogger(__name__)

GENTOO_PACKAGES_API_URL = "https://packages.gentoo.org/packages/{category}/{name}.json"


def fetch_gentoo_package_versions(category, name):
    """
    Fetch all known versions of a Gentoo package from the packages.gentoo.org API.
    Return a list of version strings.
    """
    url = GENTOO_PACKAGES_API_URL.format(category=category, name=name)
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        versions = []
        for version_info in data.get("versions", []):
            version = version_info.get("version")
            if version:
                versions.append(version)
        return versions
    except Exception as e:
        logger.error(f"Error fetching Gentoo versions for {category}/{name}: {e}")
        return []


def get_revision_versions(base_version_str, all_versions):
    """
    Given a base version string (e.g., "1.2.3") and a list of all versions,
    return a sorted list of all revisions of that base version.

    For example, if base_version_str is "1.2.3" and all_versions contains
    ["1.2.3", "1.2.3-r1", "1.2.3-r2", "1.2.4"], returns ["1.2.3", "1.2.3-r1", "1.2.3-r2"].

    Gentoo revision versions share the same base version but differ in revision
    suffix (-r0, -r1, -r2, etc.). A version without -rN is equivalent to -r0.
    """
    base = base_version_str.split("-r")[0]
    matching = []
    for v in all_versions:
        v_base = v.split("-r")[0]
        if v_base == base:
            try:
                matching.append((GentooVersion(v), v))
            except Exception:
                continue
    matching.sort(key=lambda x: x[0])
    return [v for _, v in matching]


def get_last_revision(base_version_str, all_versions):
    """
    Given a base version string and a list of all known versions,
    find the last (highest) revision of that base version.

    This is needed because Gentoo revision operators (rge, rle, rgt) apply only
    to revisions of a specific version, not to all subsequent versions.
    To create a bounded range, we use the last known revision as the upper bound.
    """
    revisions = get_revision_versions(base_version_str, all_versions)
    if revisions:
        return revisions[-1]
    return None


class GentooBasicImprover(Improver):
    """
    Improve Gentoo advisory data by fetching all known versions of affected
    ebuild packages from the packages.gentoo.org API and resolving which
    versions fall within the affected version ranges.

    This handles Gentoo's non-standard versioning by working with actual
    published versions rather than relying solely on version range arithmetic.
    """

    @property
    def interesting_advisories(self) -> QuerySet:
        return Advisory.objects.filter(
            Q(created_by=GentooImporter.qualified_name) | Q(created_by="gentoo_importer_v2")
        ).paginated()

    def get_package_versions(self, package_url: PackageURL) -> List[str]:
        """
        Fetch all known versions for a Gentoo ebuild package.
        """
        if package_url.type != "ebuild":
            return []
        category = package_url.namespace
        name = package_url.name
        if not category or not name:
            return []
        return fetch_gentoo_package_versions(category, name)

    def get_inferences(self, advisory_data: AdvisoryData) -> Iterable[Inference]:
        if not advisory_data.affected_packages:
            return

        try:
            purl, affected_version_ranges, fixed_versions = AffectedPackage.merge(
                advisory_data.affected_packages
            )
        except UnMergeablePackageError:
            logger.error(
                f"GentooBasicImprover: Cannot merge with different purls: "
                f"{advisory_data.affected_packages!r}"
            )
            for affected_package in advisory_data.affected_packages:
                yield from self._process_single_package(affected_package, advisory_data)
            return

        pkg_type = purl.type
        pkg_namespace = purl.namespace
        pkg_name = purl.name

        fixed_purls = [
            PackageURL(
                type=pkg_type,
                namespace=pkg_namespace,
                name=pkg_name,
                version=str(version),
            )
            for version in fixed_versions
        ]

        if not affected_version_ranges:
            for fixed_purl in fixed_purls:
                yield Inference.from_advisory_data(
                    advisory_data,
                    confidence=MAX_CONFIDENCE,
                    affected_purls=[],
                    fixed_purl=fixed_purl,
                )
            return

        valid_versions = self.get_package_versions(purl)
        if not valid_versions:
            return

        for affected_version_range in affected_version_ranges:
            yield from self._generate_inferences(
                affected_version_range=affected_version_range,
                pkg_type=pkg_type,
                pkg_namespace=pkg_namespace,
                pkg_name=pkg_name,
                valid_versions=valid_versions,
                advisory_data=advisory_data,
            )

    def _process_single_package(self, affected_package, advisory_data):
        """Process a single affected package that could not be merged."""
        purl = affected_package.package
        affected_version_range = affected_package.affected_version_range
        fixed_version = affected_package.fixed_version

        if not affected_version_range and fixed_version:
            yield Inference.from_advisory_data(
                advisory_data,
                confidence=MAX_CONFIDENCE,
                affected_purls=[],
                fixed_purl=PackageURL(
                    type=purl.type,
                    namespace=purl.namespace,
                    name=purl.name,
                    version=str(fixed_version),
                ),
            )
            return

        valid_versions = self.get_package_versions(purl)
        if not valid_versions:
            return

        if affected_version_range:
            yield from self._generate_inferences(
                affected_version_range=affected_version_range,
                pkg_type=purl.type,
                pkg_namespace=purl.namespace,
                pkg_name=purl.name,
                valid_versions=valid_versions,
                advisory_data=advisory_data,
            )

    def _generate_inferences(
        self,
        affected_version_range,
        pkg_type,
        pkg_namespace,
        pkg_name,
        valid_versions,
        advisory_data,
    ):
        """
        Generate Inferences by resolving the affected_version_range
        against the list of known valid_versions.
        """
        aff_vers, unaff_vers = resolve_version_range(
            affected_version_range=affected_version_range,
            ignorable_versions=[],
            package_versions=valid_versions,
        )

        affected_purls = [
            PackageURL(type=pkg_type, namespace=pkg_namespace, name=pkg_name, version=v)
            for v in aff_vers
        ]

        unaffected_purls = [
            PackageURL(type=pkg_type, namespace=pkg_namespace, name=pkg_name, version=v)
            for v in unaff_vers
        ]

        affected_packages: List[LegacyAffectedPackage] = nearest_patched_package(
            vulnerable_packages=affected_purls, resolved_packages=unaffected_purls
        )

        for (
            fixed_package,
            affected_purls,
        ) in get_affected_packages_by_patched_package(affected_packages).items():
            yield Inference.from_advisory_data(
                advisory_data,
                confidence=MAX_CONFIDENCE,
                affected_purls=affected_purls,
                fixed_purl=fixed_package,
            )
