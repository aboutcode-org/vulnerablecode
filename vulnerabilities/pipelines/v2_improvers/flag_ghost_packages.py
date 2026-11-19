#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from itertools import groupby
from traceback import format_exc as traceback_format_exc
from typing import NamedTuple

from aboutcode.pipeline import LoopProgress
from fetchcode.package_versions import SUPPORTED_ECOSYSTEMS as FETCHCODE_SUPPORTED_ECOSYSTEMS
from fetchcode.package_versions import versions
from packageurl import PackageURL
from requests import HTTPError

from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines import VulnerableCodePipeline


class PackageNotFoundError(Exception):
    """The package-level registry lookup returned HTTP 404."""


class GhostPackageCounts(NamedTuple):
    """Count missing package identities separately from individual missing versions."""

    packages: int = 0
    versions: int = 0


class FlagGhostPackagePipeline(VulnerableCodePipeline):
    """Detect and flag packages that do not exist upstream."""

    pipeline_id = "flag_ghost_packages_v2"

    # Run pipeline every 6 hours.
    run_interval = 360

    @classmethod
    def steps(cls):
        return (cls.flag_ghost_packages,)

    def flag_ghost_packages(self):
        detect_and_flag_ghost_packages(logger=self.log)


def detect_and_flag_ghost_packages(logger=None):
    """Flag unavailable packages and versions, reporting separate totals for each."""
    interesting_packages_qs = (
        PackageV2.objects.order_by("type", "namespace", "name")
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
    ghost_version_count = 0
    progress = LoopProgress(total_iterations=distinct_packages_count, logger=logger)
    for type_namespace_name, packages in progress.iter(grouped_packages):
        counts = flag_ghost_packages(
            base_purl=PackageURL(*type_namespace_name),
            packages=packages,
            logger=logger,
        )
        ghost_package_count += counts.packages
        ghost_version_count += counts.versions

    if logger:
        logger(
            f"Successfully flagged {ghost_package_count:,d} ghost packages "
            f"and {ghost_version_count:,d} ghost package versions"
        )


def flag_ghost_packages(base_purl, packages, logger=None):
    """
    Return separate counts for missing package names and missing versions.

    A missing package is reported once for its base PURL, while missing versions
    of an existing package are reported individually for PurlDB verification.
    Both keep ``is_ghost=True`` so unavailable versions cannot be suggested as fixes.
    """
    try:
        known_versions = get_versions(purl=base_purl, logger=logger)
    except PackageNotFoundError:
        flagged = False
        for pkg in packages:
            pkg.is_ghost = True
            pkg.save()
            flagged = True

        if flagged and logger:
            logger(f"Flagging ghost package {base_purl!s}", level=logging.WARNING)
        return GhostPackageCounts(packages=int(flagged))

    # Skip if encounter error while fetching known versions
    if known_versions is None:
        return GhostPackageCounts()

    ghost_versions = 0
    for pkg in packages:
        pkg.is_ghost = bool(pkg.version) and pkg.version.lstrip("vV") not in known_versions
        if pkg.is_ghost:
            ghost_versions += 1

            if logger:
                logger(
                    f"Flagging ghost package version {pkg.purl!s} for PurlDB verification",
                    level=logging.INFO,
                )
        pkg.save()

    return GhostPackageCounts(versions=ghost_versions)


def get_versions(purl, logger=None):
    """
    Return known versions, None on lookup failure, or raise PackageNotFoundError
    when a package-level registry lookup returns HTTP 404.

    Empty release lists do not establish that the package itself is missing.
    Go and GitHub lookups can fail for nested paths, version metadata or access
    permissions, so their 404s are kept as inconclusive lookup failures.
    """
    known_versions = set()
    try:
        if isinstance(purl, str):
            purl = PackageURL.from_string(purl)
        for version in versions(str(purl)):
            known_versions.add(version.value.lstrip("vV"))
        return known_versions
    except Exception as e:
        if (
            isinstance(e, HTTPError)
            and e.response is not None
            and e.response.status_code == 404
            and not known_versions
            and purl.type not in ("golang", "github")
        ):
            raise PackageNotFoundError(str(purl)) from e

        if logger:
            logger(
                f"Error while fetching known versions for {purl!s}: {e!r} \n {traceback_format_exc()}",
                level=logging.ERROR,
            )
        return
