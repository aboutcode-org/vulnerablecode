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

from aboutcode.pipeline import LoopProgress
from fetchcode.package_versions import SUPPORTED_ECOSYSTEMS as FETCHCODE_SUPPORTED_ECOSYSTEMS
from packageurl import PackageURL
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.version_range import VersionRange

from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.pipes.fetchcode_utils import get_versions
from vulnerabilities.utils import update_purl_version


class UnfurlVersionRangePipeline(VulnerableCodePipeline):

    pipeline_id = "unfurl_version_range_v2"

    @classmethod
    def steps(cls):
        return (cls.unfurl_version_range,)

    def unfurl_version_range(self):
        impacted_packages = ImpactedPackage.objects.all().order_by("-created_at")
        impacted_packages_count = impacted_packages.count()

        processed_impacted_packages_count = 0
        processed_affected_packages_count = 0
        cached_versions = {}
        self.log(f"Unfurl affected vers range for {impacted_packages_count:,d} ImpactedPackage.")
        progress = LoopProgress(total_iterations=impacted_packages_count, logger=self.log)
        for impact in progress.iter(impacted_packages):
            purl = PackageURL.from_string(impact.base_purl)
            if not impact.affecting_vers or not any(
                c in impact.affecting_vers for c in ("<", ">", "!")
            ):
                continue
            if purl.type not in FETCHCODE_SUPPORTED_ECOSYSTEMS:
                continue
            if purl.type not in RANGE_CLASS_BY_SCHEMES:
                continue

            versions = get_purl_versions(purl, cached_versions)
            affected_purls = get_affected_purls(
                versions=versions,
                affecting_vers=impact.affecting_vers,
                base_purl=purl,
                logger=self.log,
            )
            if not affected_purls:
                continue

            processed_affected_packages_count += bulk_create_with_m2m(
                purls=affected_purls,
                impact=impact,
                relation=ImpactedPackage.affecting_packages.through,
                logger=self.log,
            )
            processed_impacted_packages_count += 1

        self.log(f"Successfully processed {processed_impacted_packages_count:,d} ImpactedPackage.")
        self.log(f"{processed_affected_packages_count:,d} new Impact-Package relation created.")


def get_affected_purls(versions, affecting_vers, base_purl, logger):
    affecting_version_range = VersionRange.from_string(affecting_vers)
    version_class = affecting_version_range.version_class

    try:
        versions = [version_class(v) for v in versions]
    except Exception as e:
        logger(
            f"Error while parsing versions for {base_purl!s}: {e!r} \n {traceback_format_exc()}",
            level=logging.ERROR,
        )
        return

    affected_purls = []
    for version in versions:
        try:
            if version in affecting_version_range:
                affected_purls.append(
                    update_purl_version(
                        purl=base_purl,
                        version=str(version),
                    )
                )
        except Exception as e:
            logger(
                f"Error while checking {version!s} in {affecting_version_range!s}: {e!r} \n {traceback_format_exc()}",
                level=logging.ERROR,
            )
    return affected_purls


def get_purl_versions(purl, cached_versions):
    if not purl in cached_versions:
        cached_versions[purl] = get_versions(purl)
    return cached_versions[purl]


def bulk_create_with_m2m(purls, impact, relation, logger):
    """Bulk create PackageV2 and also bulk populate M2M Impact and Package relationships."""
    if not purls:
        return 0

    affected_packages_v2 = PackageV2.objects.bulk_get_or_create_from_purls(purls=purls)

    relations = [
        relation(impactedpackage=impact, packagev2=package) for package in affected_packages_v2
    ]

    try:
        relation.objects.bulk_create(relations, ignore_conflicts=True)
    except Exception as e:
        logger(f"Error creating ImpactedPackage {relation}: {e!r} \n {traceback_format_exc()}")
        return 0

    return len(relations)
