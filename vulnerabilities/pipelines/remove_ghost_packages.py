#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from aboutcode.pipeline import LoopProgress
from fetchcode.package_versions import SUPPORTED_ECOSYSTEMS
from fetchcode.package_versions import versions
from packageurl import PackageURL
from univers.version_range import RANGE_CLASS_BY_SCHEMES

from vulnerabilities.models import Package
from vulnerabilities.pipelines import VulnerableCodePipeline


class RemoveGhostPackagePipeline(VulnerableCodePipeline):
    @classmethod
    def steps(cls):
        return (cls.remove_ghost_packages,)

    def remove_ghost_packages(self):
        """
        Use fetchcode to validate the package indeed exists upstream.
        """
        interesting_packages_qs = (
            Package.objects.filter(type__in=SUPPORTED_ECOSYSTEMS)
            .exclude(qualifiers__isnull=True)
            .exclude(subpath__isnull=True)
        )

        distinct_packages = interesting_packages_qs.values("type", "namespace", "name").distinct(
            "type", "namespace", "name"
        )

        distinct_packages_count = distinct_packages.count()
        package_iterator = distinct_packages.iterator(chunk_size=2000)
        progress = LoopProgress(total_iterations=distinct_packages_count, logger=self.log)

        ghost_package_count = 0

        for package in progress.iter(package_iterator):
            ghost_package_count += _remove_ghost_packages(package, interesting_packages_qs)

        if self.log:
            self.log(f"Successfully removed {ghost_package_count:,d} ghost Packages")


def _remove_ghost_packages(package, interesting_packages_qs):
    if not package["type"] in RANGE_CLASS_BY_SCHEMES:
        return 0

    versionless_purl = PackageURL(**package)
    purl_type = package["type"]
    version_class = RANGE_CLASS_BY_SCHEMES[purl_type].version_class
    known_versions = [version_class(v.value) for v in versions(str(versionless_purl))]
    package_versions = interesting_packages_qs.filter(**package)

    removed_packages = 0
    for pkg in package_versions:
        if version_class(pkg.version) not in known_versions:
            pkg.delete()
            removed_packages += 1

    return removed_packages
