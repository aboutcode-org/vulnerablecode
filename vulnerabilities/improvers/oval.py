import logging
from datetime import datetime
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional

from django.db.models import Q
from django.db.models.query import QuerySet
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import UnMergeablePackageError
from vulnerabilities.importers.debian_oval import DebianOvalImporter
from vulnerabilities.importers.github import get_api_package_name
from vulnerabilities.importers.github import resolve_version_range
from vulnerabilities.importers.ubuntu import UbuntuImporter
from vulnerabilities.improver import Improver
from vulnerabilities.improver import Inference
from vulnerabilities.models import Advisory
from vulnerabilities.package_managers import DebianVersionAPI
from vulnerabilities.package_managers import LaunchpadVersionAPI
from vulnerabilities.package_managers import VersionAPI
from vulnerabilities.utils import AffectedPackage as LegacyAffectedPackage
from vulnerabilities.utils import get_affected_packages_by_patched_package
from vulnerabilities.utils import nearest_patched_package

logger = logging.getLogger(__name__)


VERSION_API_CLASS_BY_NAMESPACE = {
    "debian": DebianVersionAPI,
    "ubuntu": LaunchpadVersionAPI,
}


class OvalBasicImprover(Improver):
    def __init__(self) -> None:
        self.versions_fetcher_by_purl: Mapping[str, VersionAPI] = {}

    @property
    def interesting_advisories(self) -> QuerySet:
        return Advisory.objects.filter(
            Q(created_by=UbuntuImporter.qualified_name)
            | Q(created_by=DebianOvalImporter.qualified_name)
        )

    def get_package_versions(
        self, package_url: PackageURL, until: Optional[datetime] = None
    ) -> List[str]:
        """
        Return a list of `valid_versions` for the `package_url`
        """
        api_name = get_api_package_name(package_url)
        if not api_name:
            logger.error(f"Could not get versions for {package_url!r}")
            return []
        versions_fetcher = self.versions_fetcher_by_purl.get(package_url)
        if not versions_fetcher:
            versions_fetcher: VersionAPI = VERSION_API_CLASS_BY_NAMESPACE[package_url.namespace]
            self.versions_fetcher_by_purl[package_url] = versions_fetcher()

        versions_fetcher = self.versions_fetcher_by_purl[package_url]

        self.versions_fetcher_by_purl[package_url] = versions_fetcher
        return versions_fetcher.get_until(package_name=api_name, until=until).valid_versions

    def get_inferences(self, advisory_data: AdvisoryData) -> Iterable[Inference]:
        """
        Yield Inferences for the given advisory data
        """
        if not advisory_data.affected_packages:
            return
        try:
            purl, affected_version_ranges, _ = AffectedPackage.merge(
                advisory_data.affected_packages
            )
        except UnMergeablePackageError:
            logger.error(f"Cannot merge with different purls {advisory_data.affected_packages!r}")
            return iter([])

        pkg_type = purl.type
        pkg_namespace = purl.namespace
        pkg_name = purl.name
        valid_versions = self.get_package_versions(
            package_url=purl, until=advisory_data.date_published
        )
        for affected_version_range in affected_version_ranges:
            aff_vers, unaff_vers = resolve_version_range(
                affected_version_range=affected_version_range,
                package_versions=valid_versions,
            )
            affected_purls = [
                PackageURL(type=pkg_type, namespace=pkg_namespace, name=pkg_name, version=version)
                for version in aff_vers
            ]

            unaffected_purls = [
                PackageURL(type=pkg_type, namespace=pkg_namespace, name=pkg_name, version=version)
                for version in unaff_vers
            ]

            affected_packages: List[LegacyAffectedPackage] = nearest_patched_package(
                vulnerable_packages=affected_purls, resolved_packages=unaffected_purls
            )

            for (
                fixed_package,
                affected_packages,
            ) in get_affected_packages_by_patched_package(affected_packages).items():
                yield Inference.from_advisory_data(
                    advisory_data,
                    confidence=100,  # We are getting all valid versions to get this inference
                    affected_purls=affected_packages,
                    fixed_purl=fixed_package,
                )
