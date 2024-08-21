#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from traceback import format_exc as traceback_format_exc

from aboutcode.pipeline import LoopProgress
from fetchcode.package_versions import SUPPORTED_ECOSYSTEMS
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
    """Use fetchcode to validate the package indeed exists upstream."""
    interesting_packages_qs = (
        Package.objects.filter(type__in=SUPPORTED_ECOSYSTEMS)
        .filter(qualifiers="")
        .filter(subpath="")
    )

    distinct_packages = interesting_packages_qs.values("type", "namespace", "name").distinct(
        "type", "namespace", "name"
    )

    distinct_packages_count = distinct_packages.count()
    package_iterator = distinct_packages.iterator(chunk_size=2000)
    progress = LoopProgress(total_iterations=distinct_packages_count, logger=logger)

    ghost_package_count = 0

    for package in progress.iter(package_iterator):
        ghost_package_count += flag_ghost_package(
            package_dict=package,
            interesting_packages_qs=interesting_packages_qs,
            logger=logger,
        )

    if logger:
        logger(f"Successfully flagged {ghost_package_count:,d} ghost Packages")


def flag_ghost_package(package_dict, interesting_packages_qs, logger=None):
    """
    Check if all the versions of the package described by `package_dict` (type, namespace, name)
    are available upstream. If they are not available, update the status to 'ghost'.
    Otherwise, update the status to 'valid'.
    """
    if not package_dict["type"] in RANGE_CLASS_BY_SCHEMES:
        return 0

    known_versions = get_versions(**package_dict, logger=logger)
    if not known_versions:
        return 0

    version_class = RANGE_CLASS_BY_SCHEMES[package_dict["type"]].version_class
    package_versions = interesting_packages_qs.filter(**package_dict).filter(status="unknown")

    ghost_packages = 0
    for pkg in package_versions:
        if version_class(pkg.version) not in known_versions:
            pkg.status = "ghost"
            pkg.save()
            ghost_packages += 1

    valid_package_versions = package_versions.exclude(status="ghost")
    valid_package_versions.update(status="valid")

    return ghost_packages


def get_versions(type, namespace, name, logger=None):
    """Return set of known versions for the given package type, namespace, and name."""
    versionless_purl = PackageURL(type=type, namespace=namespace, name=name)
    version_class = RANGE_CLASS_BY_SCHEMES[type].version_class

    try:
        return {version_class(v.value) for v in versions(str(versionless_purl))}
    except Exception as e:
        if logger:
            logger(
                f"Error while fetching known versions for {versionless_purl!r}: {e!r} \n {traceback_format_exc()}",
                level=logging.ERROR,
            )
        return
