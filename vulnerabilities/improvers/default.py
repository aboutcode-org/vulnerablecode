#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from typing import Iterable
from typing import List
from typing import Tuple

from django.db.models.query import QuerySet
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.improver import MAX_CONFIDENCE
from vulnerabilities.improver import Improver
from vulnerabilities.improver import Inference
from vulnerabilities.models import Advisory
from vulnerabilities.utils import evolve_purl

logger = logging.getLogger(__name__)


class DefaultImprover(Improver):
    """
    Generate a translation of Advisory data - returned by the importers - into
    full confidence inferences. These are basic database relationships for
    unstructured data present in the Advisory model without any other
    information source.
    """

    @property
    def interesting_advisories(self) -> QuerySet:
        return Advisory.objects.all()

    def get_inferences(self, advisory_data: AdvisoryData) -> Iterable[Inference]:
        if not advisory_data:
            return []

        if advisory_data.affected_packages:
            for affected_package in advisory_data.affected_packages:
                # To deal with multiple fixed versions in a single affected package
                affected_purls, fixed_purls = get_exact_purls(affected_package)
                if not fixed_purls:
                    yield Inference(
                        aliases=advisory_data.aliases,
                        confidence=MAX_CONFIDENCE,
                        summary=advisory_data.summary,
                        affected_purls=affected_purls,
                        fixed_purl=None,
                        references=advisory_data.references,
                    )
                else:
                    for fixed_purl in fixed_purls or []:
                        yield Inference(
                            aliases=advisory_data.aliases,
                            confidence=MAX_CONFIDENCE,
                            summary=advisory_data.summary,
                            affected_purls=affected_purls,
                            fixed_purl=fixed_purl,
                            references=advisory_data.references,
                        )

        else:
            yield Inference.from_advisory_data(
                advisory_data, confidence=MAX_CONFIDENCE, fixed_purl=None
            )


def get_exact_purls(affected_package: AffectedPackage) -> Tuple[List[PackageURL], PackageURL]:
    """
    Return a list of affected purls and the fixed package found in the ``affected_package``
    AffectedPackage disregarding any ranges.

    Only exact version constraints (ie with an equality) are considered
    For eg:
    >>> purl = {"type": "turtle", "name": "green"}
    >>> vers = "vers:npm/<1.0.0 | >=2.0.0 | <3.0.0"
    >>> affected_package = AffectedPackage.from_dict({
    ...     "package": purl,
    ...     "affected_version_range": vers,
    ...     "fixed_version": "5.0.0"
    ... })
    >>> got = get_exact_purls(affected_package)
    >>> expected = (
    ...     [PackageURL(type='turtle', namespace=None, name='green', version='2.0.0', qualifiers={}, subpath=None)],
    ...     [PackageURL(type='turtle', namespace=None, name='green', version='5.0.0', qualifiers={}, subpath=None)]
    ... )
    >>> assert expected == got
    """

    vr = affected_package.affected_version_range
    # We need ``if c`` below because univers returns None as version
    # in case of vers:nginx/*
    # TODO: Revisit after https://github.com/nexB/univers/issues/33
    try:
        affected_purls = []
        fixed_versions = []
        if vr:
            range_versions = [c.version for c in vr.constraints if c]
            # Any version that's not affected by a vulnerability is considered
            # fixed.
            fixed_versions = [c.version for c in vr.constraints if c and c.comparator == "!="]
            resolved_versions = [v for v in range_versions if v and v in vr]
            for version in resolved_versions:
                affected_purl = evolve_purl(purl=affected_package.package, version=str(version))
                affected_purls.append(affected_purl)

        if affected_package.fixed_version:
            fixed_versions.append(affected_package.fixed_version)

        fixed_purls = [
            evolve_purl(purl=affected_package.package, version=str(version))
            for version in fixed_versions
        ]
        return affected_purls, fixed_purls
    except Exception as e:
        logger.error(f"Failed to get exact purls for {affected_package} {e}")
        return [], []
