#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from traceback import format_exc as traceback_format_exc
from typing import Callable
from typing import List
from typing import Tuple

from packageurl import PackageURL
from univers.version_range import VersionRange

from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.utils import update_purl_version


def get_exact_purl_from_vers(
    version_range: VersionRange, base_purl: PackageURL
) -> Tuple[List[PackageURL], List[PackageURL]]:
    """Return list of exact PURLs that in and outside vers range."""
    if not version_range:
        return [], []

    all_versions = [c.version for c in version_range.constraints if c]
    version_not_in_range = [
        c.version for c in version_range.constraints if c and c.comparator == "!="
    ]
    version_in_range = [v for v in all_versions if v and v in version_range]

    purl_in_range = [
        update_purl_version(purl=base_purl, version=str(version)) for version in version_in_range
    ]
    purl_not_in_range = [
        update_purl_version(purl=base_purl, version=str(version))
        for version in version_not_in_range
    ]

    return purl_in_range, purl_not_in_range


def get_exact_purls_v2(
    affected_package: AffectedPackageV2,
    logger: Callable = None,
) -> Tuple[List[PackageURL], PackageURL]:
    """
    Return a list of affected purls and the fixed package found in the ``affected_package``
    AffectedPackageV2 disregarding any ranges.

    Only exact version constraints (ie with an equality) are considered
    For eg:
    >>> purl = {"type": "turtle", "name": "green"}
    >>> vers = "vers:npm/<1.0.0 | >=2.0.0 | <3.0.0"
    >>> vers2 = "vers:npm/5.0.0"
    >>> affected_package = AffectedPackageV2.from_dict({
    ...     "package": purl,
    ...     "affected_version_range": vers,
    ...     "fixed_version_range": vers2
    ... })
    >>> got = get_exact_purls_v2(affected_package)
    >>> expected = (
    ...     [PackageURL(type='turtle', namespace=None, name='green', version='2.0.0', qualifiers={}, subpath=None)],
    ...     [PackageURL(type='turtle', namespace=None, name='green', version='5.0.0', qualifiers={}, subpath=None)]
    ... )
    >>> assert expected == got
    """
    if not affected_package:
        return [], []

    try:
        affected_purls, fixed_purls = get_exact_purl_from_vers(
            version_range=affected_package.affected_version_range,
            base_purl=affected_package.package,
        )

        fixed_purls_2, affected_purls_2 = get_exact_purl_from_vers(
            version_range=affected_package.fixed_version_range,
            base_purl=affected_package.package,
        )

        affected_purls.extend(affected_purls_2)
        fixed_purls.extend(fixed_purls_2)

        return affected_purls, fixed_purls
    except Exception as e:
        logger(
            f"Failed to get exact purls for: {affected_package!r} with error: {e!r} \n{traceback_format_exc()}",
            level=logging.ERROR,
        )
        return [], []
