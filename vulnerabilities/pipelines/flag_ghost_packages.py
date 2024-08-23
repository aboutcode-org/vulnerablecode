#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from itertools import groupby
from traceback import format_exc as traceback_format_exc

from aboutcode.pipeline import LoopProgress
from fetchcode.package_versions import SUPPORTED_ECOSYSTEMS as FETCHCODE_SUPPORTED_ECOSYSTEMS
from fetchcode.package_versions import versions
from packageurl import PackageURL
from univers.version_range import RANGE_CLASS_BY_SCHEMES

from vulnerabilities.models import Package
from vulnerabilities.pipelines import VulnerableCodePipeline


class FlagGhostPackagePipeline(VulnerableCodePipeline):
    """Detect and flag packages that do not exist upstream."""

    @classmethod
    def steps(cls):
        return (cls.flag_ghost_packages,)

    def flag_ghost_packages(self):
        detect_and_flag_ghost_packages(logger=self.log)


def detect_and_flag_ghost_packages(logger=None):
    """Check if packages are available upstream. If not, mark them as ghost package."""
    interesting_packages_qs = (
        Package.objects.order_by("type", "namespace", "name")
        .filter(type__in=FETCHCODE_SUPPORTED_ECOSYSTEMS)
        .filter(qualifiers="")
        .filter(subpath="")
    )

    distinct_packages_count = (
        interesting_packages_qs.values("type", "namespace", "name")
        .distinct("type", "namespace", "name")
        .count()
    )

    grouped_packages = groupby(
        interesting_packages_qs.paginated(),
        key=lambda pkg: (pkg.type, pkg.namespace, pkg.name),
    )

    ghost_package_count = 0
    progress = LoopProgress(total_iterations=distinct_packages_count, logger=logger)
    for type_namespace_name, packages in progress.iter(grouped_packages):
        ghost_package_count += flag_ghost_package(
            base_purl=PackageURL(*type_namespace_name),
            packages=packages,
            logger=logger,
        )

    if logger:
        logger(f"Successfully flagged {ghost_package_count:,d} ghost Packages")


def flag_ghost_package(base_purl, packages, logger=None):
    """
    Check if all the versions of the `purl` are available upstream.
    If they are not available, update the `is_ghost` to `True`.
    """
    if not base_purl.type in RANGE_CLASS_BY_SCHEMES:
        return 0

    known_versions = get_versions(purl=base_purl, logger=logger)
    # Skip if encounter error while fetching known versions
    if known_versions is None:
        return 0

    ghost_packages = 0
    version_class = RANGE_CLASS_BY_SCHEMES[base_purl.type].version_class
    for pkg in packages:
        pkg.is_ghost = False
        if version_class(pkg.version) not in known_versions:
            pkg.is_ghost = True
            ghost_packages += 1

            if logger:
                logger(f"Flagging ghost package {pkg.purl!s}", level=logging.DEBUG)
        pkg.save()

    return ghost_packages


def get_versions(purl, logger=None):
    """Return set of known versions for the given purl."""
    version_class = RANGE_CLASS_BY_SCHEMES[purl.type].version_class

    try:
        return {version_class(v.value) for v in versions(str(purl))}
    except Exception as e:
        if logger:
            logger(
                f"Error while fetching known versions for {purl!s}: {e!r} \n {traceback_format_exc()}",
                level=logging.ERROR,
            )
        return
